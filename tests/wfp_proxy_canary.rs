//! P0 的 Windows 原生 WFP 代理出口探针（**不安装持久规则**）。
//!
//! 只对本测试 exe 的 WFP AppId 安装动态会话过滤器，测试结束/进程退出由 BFE
//! 自动移除；不修改 SpiderVPN 的正式 provider、subLayer、交易名单或用户防火墙。
//!
//! 显式运行：
//!   $env:SPIDERVPN_WFP_CANARY='1'
//!   cargo test --locked --test wfp_proxy_canary -- --ignored --test-threads=1 --nocapture
//!
//! 这只验证 IPv4 环回出口的 WFP 匹配与 BLOCK 仲裁，不能替代 TUN + IPv6 实机验证。

#[cfg(not(windows))]
#[test]
fn canary_only_runs_on_windows() {}

#[cfg(windows)]
mod windows_canary {
    use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};
    use std::time::Duration;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform as W;

    /// 不返回持久句柄：本探针的所有 WFP 对象都归动态会话。
    struct DynamicEngine(HANDLE);

    impl DynamicEngine {
        fn open() -> Self {
            let mut session = W::FWPM_SESSION0::default();
            session.flags = W::FWPM_SESSION_FLAG_DYNAMIC;
            let mut handle: HANDLE = null_mut();
            let rc = unsafe { W::FwpmEngineOpen0(null(), 10, null(), &session, &mut handle) };
            assert_eq!(rc, 0, "WFP 动态会话无法打开：0x{rc:08X}（CI 必须能提权）");
            assert!(!handle.is_null());
            DynamicEngine(handle)
        }
    }

    impl Drop for DynamicEngine {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { W::FwpmEngineClose0(self.0); }
                self.0 = null_mut();
            }
        }
    }

    struct AppId(*mut W::FWP_BYTE_BLOB);

    impl AppId {
        fn this_test_exe() -> Self {
            let path = std::env::current_exe().expect("当前测试程序路径");
            let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            let mut blob: *mut W::FWP_BYTE_BLOB = null_mut();
            let rc = unsafe { W::FwpmGetAppIdFromFileName0(wide.as_ptr(), &mut blob) };
            assert_eq!(rc, 0, "获取测试程序 WFP AppId 失败：0x{rc:08X}");
            assert!(!blob.is_null());
            AppId(blob)
        }
    }

    impl Drop for AppId {
        fn drop(&mut self) {
            if !self.0.is_null() {
                let mut ptr = self.0.cast::<core::ffi::c_void>();
                unsafe { W::FwpmFreeMemory0(&mut ptr); }
                self.0 = null_mut();
            }
        }
    }

    #[derive(Clone, Copy)]
    enum DenyKind { WrongIp, WrongPort, NotTcp }

    fn install_filter(engine: &DynamicEngine, app: &AppId, port: u16, kind: DenyKind) -> u64 {
        let app_condition = W::FWPM_FILTER_CONDITION0 {
            fieldKey: W::FWPM_CONDITION_ALE_APP_ID,
            matchType: W::FWP_MATCH_EQUAL,
            conditionValue: W::FWP_CONDITION_VALUE0 {
                r#type: W::FWP_BYTE_BLOB_TYPE,
                Anonymous: W::FWP_CONDITION_VALUE0_0 { byteBlob: app.0 },
            },
        };
        // 这里必须是三条独立过滤器，每条 APP_ID + 一个 NOT_EQUAL：
        // 地址不同 OR 端口不同 OR 非 TCP 都阻断。
        let destination_condition = match kind {
            DenyKind::WrongIp => W::FWPM_FILTER_CONDITION0 {
                fieldKey: W::FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType: W::FWP_MATCH_NOT_EQUAL,
                conditionValue: W::FWP_CONDITION_VALUE0 {
                    r#type: W::FWP_UINT32,
                    // WFP IPv4 地址必须按 host-order 数值存储。
                    Anonymous: W::FWP_CONDITION_VALUE0_0 {
                        uint32: u32::from_be_bytes([127, 0, 0, 1]),
                    },
                },
            },
            DenyKind::WrongPort => W::FWPM_FILTER_CONDITION0 {
                fieldKey: W::FWPM_CONDITION_IP_REMOTE_PORT,
                matchType: W::FWP_MATCH_NOT_EQUAL,
                conditionValue: W::FWP_CONDITION_VALUE0 {
                    r#type: W::FWP_UINT16,
                    Anonymous: W::FWP_CONDITION_VALUE0_0 { uint16: port },
                },
            },
            DenyKind::NotTcp => W::FWPM_FILTER_CONDITION0 {
                fieldKey: W::FWPM_CONDITION_IP_PROTOCOL,
                matchType: W::FWP_MATCH_NOT_EQUAL,
                conditionValue: W::FWP_CONDITION_VALUE0 {
                    r#type: W::FWP_UINT8,
                    Anonymous: W::FWP_CONDITION_VALUE0_0 { uint8: 6 },
                },
            },
        };
        let mut conditions = [app_condition, destination_condition];
        let mut name: Vec<u16> = "SpiderVPN temporary WFP canary".encode_utf16().chain(Some(0)).collect();
        // 不复用正式 provider GUID、不使用 PERSISTENT flag、不引用正式 sublayer。
        let mut raw = W::FWPM_FILTER0::default();
        raw.displayData.name = name.as_mut_ptr();
        raw.layerKey = W::FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        raw.subLayerKey = W::FWPM_SUBLAYER_UNIVERSAL;
        raw.weight = W::FWP_VALUE0 {
            r#type: W::FWP_UINT8,
            Anonymous: W::FWP_VALUE0_0 { uint8: 13 },
        };
        raw.numFilterConditions = conditions.len() as u32;
        raw.filterCondition = conditions.as_mut_ptr();
        raw.action = W::FWPM_ACTION0 {
            r#type: W::FWP_ACTION_BLOCK,
            Anonymous: W::FWPM_ACTION0_0 { filterType: windows_sys::core::GUID::default() },
        };
        let mut id = 0u64;
        let rc = unsafe { W::FwpmFilterAdd0(engine.0, &raw, null_mut(), &mut id) };
        assert_eq!(rc, 0, "安装动态代理过滤器失败：0x{rc:08X}");
        assert_ne!(id, 0);
        id
    }

    /// 与 IPv4 对称的 IPv6 探针：FWP_BYTE_ARRAY16_TYPE 必须指向整个 16 字节。
    /// 不可把 ::1 当成 IPv4 127.0.0.1 的隐式别名。
    fn install_filter_v6(engine: &DynamicEngine, app: &AppId, port: u16, kind: DenyKind) {
        let app_condition = W::FWPM_FILTER_CONDITION0 {
            fieldKey: W::FWPM_CONDITION_ALE_APP_ID,
            matchType: W::FWP_MATCH_EQUAL,
            conditionValue: W::FWP_CONDITION_VALUE0 {
                r#type: W::FWP_BYTE_BLOB_TYPE,
                Anonymous: W::FWP_CONDITION_VALUE0_0 { byteBlob: app.0 },
            },
        };
        let mut loopback = W::FWP_BYTE_ARRAY16 { byteArray16: [0; 16] };
        loopback.byteArray16[15] = 1; // ::1
        let destination_condition = match kind {
            DenyKind::WrongIp => W::FWPM_FILTER_CONDITION0 {
                fieldKey: W::FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType: W::FWP_MATCH_NOT_EQUAL,
                conditionValue: W::FWP_CONDITION_VALUE0 {
                    r#type: W::FWP_BYTE_ARRAY16_TYPE,
                    Anonymous: W::FWP_CONDITION_VALUE0_0 { byteArray16: &mut loopback },
                },
            },
            DenyKind::WrongPort => W::FWPM_FILTER_CONDITION0 {
                fieldKey: W::FWPM_CONDITION_IP_REMOTE_PORT,
                matchType: W::FWP_MATCH_NOT_EQUAL,
                conditionValue: W::FWP_CONDITION_VALUE0 {
                    r#type: W::FWP_UINT16,
                    Anonymous: W::FWP_CONDITION_VALUE0_0 { uint16: port },
                },
            },
            DenyKind::NotTcp => W::FWPM_FILTER_CONDITION0 {
                fieldKey: W::FWPM_CONDITION_IP_PROTOCOL,
                matchType: W::FWP_MATCH_NOT_EQUAL,
                conditionValue: W::FWP_CONDITION_VALUE0 {
                    r#type: W::FWP_UINT8,
                    Anonymous: W::FWP_CONDITION_VALUE0_0 { uint8: 6 },
                },
            },
        };
        let mut conditions = [app_condition, destination_condition];
        let mut name: Vec<u16> = "SpiderVPN temporary IPv6 WFP canary"
            .encode_utf16().chain(Some(0)).collect();
        let mut raw = W::FWPM_FILTER0::default();
        raw.displayData.name = name.as_mut_ptr();
        raw.layerKey = W::FWPM_LAYER_ALE_AUTH_CONNECT_V6;
        raw.subLayerKey = W::FWPM_SUBLAYER_UNIVERSAL;
        raw.weight = W::FWP_VALUE0 {
            r#type: W::FWP_UINT8,
            Anonymous: W::FWP_VALUE0_0 { uint8: 13 },
        };
        raw.numFilterConditions = conditions.len() as u32;
        raw.filterCondition = conditions.as_mut_ptr();
        raw.action = W::FWPM_ACTION0 {
            r#type: W::FWP_ACTION_BLOCK,
            Anonymous: W::FWPM_ACTION0_0 { filterType: windows_sys::core::GUID::default() },
        };
        let mut id = 0u64;
        let rc = unsafe { W::FwpmFilterAdd0(engine.0, &raw, null_mut(), &mut id) };
        assert_eq!(rc, 0, "安装动态 IPv6 代理过滤器失败：0x{rc:08X}");
        assert_ne!(id, 0);
    }

    /// 仅验证 ALE_AUTH_CONNECT_V4 在环回场景是否提供下一跳 LUID，
    /// 绝不能把此测试结果冒充真正 Wintun 接口的分类结论。
    fn install_next_hop_probe(engine: &DynamicEngine, app: &AppId, match_empty: bool) {
        let app_cond = W::FWPM_FILTER_CONDITION0 {
            fieldKey: W::FWPM_CONDITION_ALE_APP_ID,
            matchType: W::FWP_MATCH_EQUAL,
            conditionValue: W::FWP_CONDITION_VALUE0 {
                r#type: W::FWP_BYTE_BLOB_TYPE,
                Anonymous: W::FWP_CONDITION_VALUE0_0 { byteBlob: app.0 },
            },
        };
        let mut invalid_luid: u64 = 0;
        let next_cond = if match_empty {
            // Microsoft ALE reauthorization documentation: unknown interface fields
            // are represented by FWP_EMPTY, which can be matched with EQUAL.
            W::FWPM_FILTER_CONDITION0 {
                fieldKey: W::FWPM_CONDITION_IP_NEXTHOP_INTERFACE,
                matchType: W::FWP_MATCH_EQUAL,
                conditionValue: W::FWP_CONDITION_VALUE0 {
                    r#type: W::FWP_EMPTY,
                    Anonymous: unsafe { std::mem::zeroed() },
                },
            }
        } else {
            W::FWPM_FILTER_CONDITION0 {
                fieldKey: W::FWPM_CONDITION_IP_NEXTHOP_INTERFACE,
                matchType: W::FWP_MATCH_NOT_EQUAL,
                conditionValue: W::FWP_CONDITION_VALUE0 {
                    r#type: W::FWP_UINT64,
                    Anonymous: W::FWP_CONDITION_VALUE0_0 { uint64: &mut invalid_luid },
                },
            }
        };
        let mut conditions = [app_cond, next_cond];
        let mut name: Vec<u16> = "SpiderVPN temporary next-hop WFP probe"
            .encode_utf16().chain(Some(0)).collect();
        let mut raw = W::FWPM_FILTER0::default();
        raw.displayData.name = name.as_mut_ptr();
        raw.layerKey = W::FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        raw.subLayerKey = W::FWPM_SUBLAYER_UNIVERSAL;
        raw.weight = W::FWP_VALUE0 {
            r#type: W::FWP_UINT8,
            Anonymous: W::FWP_VALUE0_0 { uint8: 13 },
        };
        raw.numFilterConditions = conditions.len() as u32;
        raw.filterCondition = conditions.as_mut_ptr();
        raw.action = W::FWPM_ACTION0 {
            r#type: W::FWP_ACTION_BLOCK,
            Anonymous: W::FWPM_ACTION0_0 { filterType: windows_sys::core::GUID::default() },
        };
        let mut id = 0u64;
        let rc = unsafe { W::FwpmFilterAdd0(engine.0, &raw, null_mut(), &mut id) };
        assert_eq!(rc, 0, "下一跳 LUID 探针无法安装：0x{rc:08X}");
        assert_ne!(id, 0);
    }

    /// 模拟正式旧版本：只有 ALE_APP_ID 条件的宽泛 BLOCK。
    /// 测试 exe 自己作为名单程序，动态会话退出后无需卸载。
    fn install_legacy_block(engine: &DynamicEngine, app: &AppId) -> u64 {
        let mut cond = [W::FWPM_FILTER_CONDITION0 {
            fieldKey: W::FWPM_CONDITION_ALE_APP_ID,
            matchType: W::FWP_MATCH_EQUAL,
            conditionValue: W::FWP_CONDITION_VALUE0 {
                r#type: W::FWP_BYTE_BLOB_TYPE,
                Anonymous: W::FWP_CONDITION_VALUE0_0 { byteBlob: app.0 },
            },
        }];
        let mut name: Vec<u16> = "SpiderVPN legacy migration canary".encode_utf16().chain(Some(0)).collect();
        let mut raw = W::FWPM_FILTER0::default();
        raw.displayData.name = name.as_mut_ptr();
        raw.layerKey = W::FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        raw.subLayerKey = W::FWPM_SUBLAYER_UNIVERSAL;
        raw.weight = W::FWP_VALUE0 {
            r#type: W::FWP_UINT8,
            Anonymous: W::FWP_VALUE0_0 { uint8: 13 },
        };
        raw.numFilterConditions = 1;
        raw.filterCondition = cond.as_mut_ptr();
        raw.action = W::FWPM_ACTION0 {
            r#type: W::FWP_ACTION_BLOCK,
            Anonymous: W::FWPM_ACTION0_0 { filterType: windows_sys::core::GUID::default() },
        };
        let mut id = 0u64;
        let rc = unsafe { W::FwpmFilterAdd0(engine.0, &raw, null_mut(), &mut id) };
        assert_eq!(rc, 0, "无法安装只供测试的旧宽泛规则：0x{rc:08X}");
        assert_ne!(id, 0);
        id
    }

    /// WFP 备选的 fail-closed 架构验证：长期 BLOCK 在同一个 sublayer 中保持，
    /// 仅引擎健康期间开启权重更高的“精确代理端点”动态 PERMIT。
    ///
    /// 动态 PERMIT 不带 CLEAR_ACTION_RIGHT，仍允许其它安全产品阻断连接；
    /// 它只应在同一 sublayer 中提前命中、绕过我们的宽泛 BLOCK。
    fn install_ephemeral_proxy_permit(engine: &DynamicEngine, app: &AppId, port: u16) {
        let mut conditions = [
            W::FWPM_FILTER_CONDITION0 {
                fieldKey: W::FWPM_CONDITION_ALE_APP_ID,
                matchType: W::FWP_MATCH_EQUAL,
                conditionValue: W::FWP_CONDITION_VALUE0 {
                    r#type: W::FWP_BYTE_BLOB_TYPE,
                    Anonymous: W::FWP_CONDITION_VALUE0_0 { byteBlob: app.0 },
                },
            },
            W::FWPM_FILTER_CONDITION0 {
                fieldKey: W::FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType: W::FWP_MATCH_EQUAL,
                conditionValue: W::FWP_CONDITION_VALUE0 {
                    r#type: W::FWP_UINT32,
                    Anonymous: W::FWP_CONDITION_VALUE0_0 {
                        uint32: u32::from_be_bytes([127, 0, 0, 1]),
                    },
                },
            },
            W::FWPM_FILTER_CONDITION0 {
                fieldKey: W::FWPM_CONDITION_IP_REMOTE_PORT,
                matchType: W::FWP_MATCH_EQUAL,
                conditionValue: W::FWP_CONDITION_VALUE0 {
                    r#type: W::FWP_UINT16,
                    Anonymous: W::FWP_CONDITION_VALUE0_0 { uint16: port },
                },
            },
            W::FWPM_FILTER_CONDITION0 {
                fieldKey: W::FWPM_CONDITION_IP_PROTOCOL,
                matchType: W::FWP_MATCH_EQUAL,
                conditionValue: W::FWP_CONDITION_VALUE0 {
                    r#type: W::FWP_UINT8,
                    Anonymous: W::FWP_CONDITION_VALUE0_0 { uint8: 6 },
                },
            },
        ];
        let mut name: Vec<u16> = "SpiderVPN soft permit lifecycle canary"
            .encode_utf16().chain(Some(0)).collect();
        let mut raw = W::FWPM_FILTER0::default();
        raw.displayData.name = name.as_mut_ptr();
        raw.layerKey = W::FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        raw.subLayerKey = W::FWPM_SUBLAYER_UNIVERSAL;
        raw.weight = W::FWP_VALUE0 {
            r#type: W::FWP_UINT8,
            Anonymous: W::FWP_VALUE0_0 { uint8: 14 }, // higher priority than broad BLOCK (13)
        };
        raw.numFilterConditions = conditions.len() as u32;
        raw.filterCondition = conditions.as_mut_ptr();
        raw.action = W::FWPM_ACTION0 {
            r#type: W::FWP_ACTION_PERMIT,
            Anonymous: W::FWPM_ACTION0_0 { filterType: windows_sys::core::GUID::default() },
        };
        raw.flags = 0; // nonpersistent, soft PERMIT
        let mut id = 0u64;
        let rc = unsafe { W::FwpmFilterAdd0(engine.0, &raw, null_mut(), &mut id) };
        assert_eq!(rc, 0, "安装非持久精确代理 PERMIT 失败：0x{rc:08X}");
        assert_ne!(id, 0);
    }

    fn begin_txn(engine: &DynamicEngine) {
        let rc = unsafe { W::FwpmTransactionBegin0(engine.0, 0) };
        assert_eq!(rc, 0, "开始 WFP 原子迁移事务失败：0x{rc:08X}");
    }

    fn delete_filter(engine: &DynamicEngine, filter_id: u64) {
        let rc = unsafe { W::FwpmFilterDeleteById0(engine.0, filter_id) };
        assert_eq!(rc, 0, "在事务内删除测试规则失败：0x{rc:08X}");
    }

    fn commit_txn(engine: &DynamicEngine) {
        let rc = unsafe { W::FwpmTransactionCommit0(engine.0) };
        assert_eq!(rc, 0, "WFP 原子迁移提交失败：0x{rc:08X}");
    }

    fn abort_txn(engine: &DynamicEngine) {
        let rc = unsafe { W::FwpmTransactionAbort0(engine.0) };
        assert_eq!(rc, 0, "WFP 原子迁移回滚失败：0x{rc:08X}");
    }

    fn connect(addr: SocketAddr) -> std::io::Result<TcpStream> {
        TcpStream::connect_timeout(&addr, Duration::from_millis(700))
    }

    /// 每次创建一个新的 UDP socket，避免复用安装过滤器之前已获准的 ALE 流。
    /// 检查实际送达服务端，而不只看 connect()/send() 的表面返回值。
    fn udp_reaches(server: &UdpSocket, destination: SocketAddr) -> bool {
        let bind = if destination.is_ipv4() { "127.0.0.1:0" } else { "[::1]:0" };
        let client = UdpSocket::bind(bind).expect("为当前探针建立新 UDP socket");
        server.set_read_timeout(Some(Duration::from_millis(450))).unwrap();
        if client.connect(destination).is_err() || client.send(b"vpn-wfp-test").is_err() {
            return false;
        }
        let mut buffer = [0u8; 128];
        matches!(server.recv_from(&mut buffer), Ok((n, _)) if &buffer[..n] == b"vpn-wfp-test")
    }

    // 用当前 Rust 测试 exe 充当独立 WFP lease 进程。只有显式 child 标记
    // 才能安装；没有标记就原样返回，普通测试永不启动常驻进程。
    #[test]
    #[ignore = "供 crash canary 子进程独立调用，普通测试禁止运行"]
    fn wfp_soft_permit_child() {
        if std::env::var("SPIDERVPN_WFP_LEASE_CHILD").as_deref() != Ok("1") {
            return;
        }
        assert_eq!(std::env::var("SPIDERVPN_WFP_CANARY").as_deref(), Ok("1"));
        let port: u16 = std::env::var("SPIDERVPN_WFP_LEASE_PORT").unwrap()
            .parse().expect("子进程必须得到端口");
        let signal = std::path::PathBuf::from(
            std::env::var_os("SPIDERVPN_WFP_LEASE_READY").expect("子进程必须得到握手路径"));
        let session = DynamicEngine::open();
        let app = AppId::this_test_exe();
        install_ephemeral_proxy_permit(&session, &app, port);
        std::fs::write(&signal, b"ready").expect("已安装 WFP 动态 PERMIT 才能声明就绪");
        // 父进程会强制 kill；该会话绝不能通过显式 Drop 才关闭。
        loop { std::thread::sleep(Duration::from_millis(100)); }
    }

    /// 保证崩溃测试中的拒绝不是由没有 accept 的 TCP backlog 填满造成的。
    /// 后台持续取出所有已允许连接，失败判据才能归因于 WFP 策略而不是监听队列。
    struct ListenerDrain {
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }
    impl ListenerDrain {
        fn start(listener: &TcpListener) -> Self {
            use std::sync::atomic::{AtomicBool, Ordering};
            let listener = listener.try_clone().unwrap();
            listener.set_nonblocking(true).unwrap();
            let stop = std::sync::Arc::new(AtomicBool::new(false));
            let flag = stop.clone();
            let thread = std::thread::spawn(move || {
                while !flag.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((connection, _)) => drop(connection),
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock =>
                            std::thread::sleep(Duration::from_millis(10)),
                        Err(_) => break,
                    }
                }
            });
            Self { stop, thread: Some(thread) }
        }
    }
    impl Drop for ListenerDrain {
        fn drop(&mut self) {
            use std::sync::atomic::Ordering;
            self.stop.store(true, Ordering::Relaxed);
            if let Some(thread) = self.thread.take() { let _ = thread.join(); }
        }
    }

    struct KillChild(std::process::Child);
    impl Drop for KillChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    #[ignore = "CI 在隔离 Windows 中实际杀死持有动态 WFP PERMIT 的独立进程，验证 RPC rundown"]
    fn ephemeral_permit_disappears_after_ungraceful_owner_process_kill() {
        use std::process::{Command, Stdio};
        use std::time::Instant;

        assert_eq!(std::env::var("SPIDERVPN_WFP_CANARY").as_deref(), Ok("1"));
        let trusted = TcpListener::bind("127.0.0.1:0").unwrap();
        let other = TcpListener::bind("127.0.0.1:0").unwrap();
        let trusted_addr = trusted.local_addr().unwrap();
        let other_addr = other.local_addr().unwrap();
        let _trusted_drain = ListenerDrain::start(&trusted);
        let _other_drain = ListenerDrain::start(&other);
        assert!(connect(trusted_addr).is_ok() && connect(other_addr).is_ok());

        let baseline = DynamicEngine::open();
        let app = AppId::this_test_exe();
        install_legacy_block(&baseline, &app);
        assert!(connect(trusted_addr).is_err() && connect(other_addr).is_err());

        let ready = std::env::temp_dir().join(format!(
            "spidervpn-wfp-lease-{}-{}.signal", std::process::id(), trusted_addr.port()));
        let _ = std::fs::remove_file(&ready);
        let mut child = KillChild(
            Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact", "windows_canary::wfp_soft_permit_child", "--nocapture"])
                .env("SPIDERVPN_WFP_LEASE_CHILD", "1")
                .env("SPIDERVPN_WFP_LEASE_PORT", trusted_addr.port().to_string())
                .env("SPIDERVPN_WFP_LEASE_READY", &ready)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn().expect("创建独立动态 WFP lease 子进程失败")
        );
        let start = Instant::now();
        while !ready.exists() {
            if let Ok(Some(status)) = child.0.try_wait() {
                panic!("动态 PERMIT 子进程提前退出（{status}），不得据此声称 fail-closed");
            }
            assert!(start.elapsed() < Duration::from_secs(10), "子进程未安装并确认动态 PERMIT");
            std::thread::sleep(Duration::from_millis(50));
        }

        assert!(connect(trusted_addr).is_ok(), "子进程临时 PERMIT 未放行指定端口");
        assert!(connect(other_addr).is_err(), "临时 PERMIT 意外放行了其他端口");

        // kill，不能通过 Drop 正常关闭 WFP 句柄；WFP 必须因 owner 进程结束清理。
        child.0.kill().expect("模拟持有 PERMIT 进程突然崩溃");
        child.0.wait().expect("等待子进程完全退出");
        let start = Instant::now();
        loop {
            if connect(trusted_addr).is_err() { break; }
            assert!(start.elapsed() < Duration::from_secs(5),
                "owner 已退出但新连接仍能通过原 PERMIT，存在断线泄漏");
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(connect(other_addr).is_err());
        drop(baseline);
        assert!(connect(trusted_addr).is_ok() && connect(other_addr).is_ok());
        let _ = std::fs::remove_file(ready);
    }

    #[test]
    #[ignore = "CI 仅针对测试 exe 的 WFP 动态双会话；验证常驻 BLOCK + 临时精确 PERMIT 的仲裁和撤销"]
    fn persistent_style_block_plus_ephemeral_permit_fails_closed_on_session_exit() {
        assert_eq!(std::env::var("SPIDERVPN_WFP_CANARY").as_deref(), Ok("1"));
        let allowed = TcpListener::bind("127.0.0.1:0").unwrap();
        let other = TcpListener::bind("127.0.0.1:0").unwrap();
        let allowed_addr = allowed.local_addr().unwrap();
        let other_addr = other.local_addr().unwrap();
        assert!(connect(allowed_addr).is_ok() && connect(other_addr).is_ok());

        // A 会话模拟“始终在位的 BLOCK”（CI 中保持动态以保证绝不残留）；
        // B 会话只临时放行特定代理端点，退出自动失效。
        let permanent_simulation = DynamicEngine::open();
        let app = AppId::this_test_exe();
        install_legacy_block(&permanent_simulation, &app);
        assert!(connect(allowed_addr).is_err() && connect(other_addr).is_err(),
            "基础规则没有做到无例外默认 BLOCK");

        let permit_session = DynamicEngine::open();
        install_ephemeral_proxy_permit(&permit_session, &app, allowed_addr.port());
        assert!(connect(allowed_addr).is_ok(),
            "较高权重的同子层精确 PERMIT 未能放行可信端点，架构不能发布");
        assert!(connect(other_addr).is_err(), "更高权重 PERMIT 意外放行了非信任端口");

        drop(permit_session);
        assert!(connect(allowed_addr).is_err() && connect(other_addr).is_err(),
            "临时 PERMIT 会话消失后没有恢复全阻断，断线防泄漏失败");

        drop(permanent_simulation);
        assert!(connect(allowed_addr).is_ok() && connect(other_addr).is_ok(),
            "模拟基础 BLOCK 关闭后残留过滤器，可能污染 CI 或用户系统");
    }

    #[test]
    #[ignore = "真实 WFP 原子迁移及回滚，仅隔离 Windows runner 显式执行"]
    fn atomic_migration_and_abort_preserve_exact_proxy_policy() {
        assert_eq!(std::env::var("SPIDERVPN_WFP_CANARY").as_deref(), Ok("1"));
        let a = TcpListener::bind("127.0.0.1:0").unwrap();
        let b = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr_a = a.local_addr().unwrap();
        let addr_b = b.local_addr().unwrap();
        assert!(connect(addr_a).is_ok() && connect(addr_b).is_ok(),
            "过滤前两种 TCP 连接都要真正可用");

        let engine = DynamicEngine::open();
        let app = AppId::this_test_exe();
        let old = install_legacy_block(&engine, &app);
        assert!(connect(addr_a).is_err() && connect(addr_b).is_err(),
            "旧 v1 APP_ID 宽泛 BLOCK 应阻断所有新 TCP 连接");

        begin_txn(&engine);
        delete_filter(&engine, old);
        let mut scoped = Vec::new();
        for kind in [DenyKind::WrongIp, DenyKind::WrongPort, DenyKind::NotTcp] {
            scoped.push(install_filter(&engine, &app, addr_a.port(), kind));
        }
        commit_txn(&engine);
        assert!(connect(addr_a).is_ok(), "原子迁移后可信代理应可用");
        assert!(connect(addr_b).is_err(), "原子迁移后不应放行其他代理端口");

        // 模拟端口变更事务中途失败：直接 abort，旧的可用策略必须完整留下。
        begin_txn(&engine);
        for id in &scoped { delete_filter(&engine, *id); }
        for kind in [DenyKind::WrongIp, DenyKind::WrongPort, DenyKind::NotTcp] {
            install_filter(&engine, &app, addr_b.port(), kind);
        }
        abort_txn(&engine);
        assert!(connect(addr_a).is_ok(), "事务 abort 后先前的合法代理端口必须保留");
        assert!(connect(addr_b).is_err(), "事务 abort 不得产生新的绕过端口");

        // 成功的端口切换也要求同一事务中撤旧建新。
        begin_txn(&engine);
        for id in &scoped { delete_filter(&engine, *id); }
        for kind in [DenyKind::WrongIp, DenyKind::WrongPort, DenyKind::NotTcp] {
            install_filter(&engine, &app, addr_b.port(), kind);
        }
        commit_txn(&engine);
        assert!(connect(addr_a).is_err(), "成功变更后旧端口必须失效");
        assert!(connect(addr_b).is_ok(), "新端口必须接替旧端口");
        drop(engine);
        assert!(connect(addr_a).is_ok() && connect(addr_b).is_ok(),
            "动态会话结束后所有旧/新测试规则都必须消失");
    }

    #[test]
    #[ignore = "原生下一跳 LUID 探针，仅隔离 Windows 运行器显式执行"]
    fn next_hop_luid_is_present_for_ipv4_loopback_authorization() {
        assert_eq!(std::env::var("SPIDERVPN_WFP_CANARY").as_deref(), Ok("1"));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(connect(addr).is_ok(), "探针前本地 TCP 必须能连通");
        let engine = DynamicEngine::open();
        let app = AppId::this_test_exe();
        install_next_hop_probe(&engine, &app, false);
        assert!(connect(addr).is_err(),
            "ALE_AUTH_CONNECT 未把环回下一跳 LUID 纳入 NOT_EQUAL 分类；不能据此部署 TUN 策略");
        drop(engine);
        assert!(connect(addr).is_ok(), "探针关闭动态会话后应恢复网络");

        // FWP_EMPTY 原生过滤器必须能够安装，且在“下一跳已知”的初始
        // 授权中不应误阻断。该测试不假装已经触发真实 TUN 重新授权。
        let empty_engine = DynamicEngine::open();
        install_next_hop_probe(&empty_engine, &app, true);
        assert!(connect(addr).is_ok(), "非空下一跳错误匹配了 FWP_EMPTY 防泄漏规则");
        drop(empty_engine);
        assert!(connect(addr).is_ok());
    }

    #[test]
    #[ignore = "仅隔离 Windows CI 显式启用，与 IPv4 canary 对称"]
    fn ipv6_proxy_port_is_exact_and_dynamic_filters_are_removed() {
        assert_eq!(std::env::var("SPIDERVPN_WFP_CANARY").as_deref(), Ok("1"),
            "需显式设置 SPIDERVPN_WFP_CANARY=1");
        let trusted = TcpListener::bind("[::1]:0").expect("Windows IPv6 回环必须可用");
        let other = TcpListener::bind("[::1]:0").expect("IPv6 非白名单端口");
        let trusted_addr = trusted.local_addr().unwrap();
        let other_addr = other.local_addr().unwrap();
        assert!(connect(trusted_addr).is_ok());
        assert!(connect(other_addr).is_ok());
        let udp_server = UdpSocket::bind(("[::1]", trusted_addr.port()))
            .expect("在 IPv6 可信 TCP 代理端口旁建立 UDP 负对照");
        assert!(udp_reaches(&udp_server, udp_server.local_addr().unwrap()),
            "IPv6 UDP 在安装 WFP 前必须真正送达");

        let engine = DynamicEngine::open();
        let app = AppId::this_test_exe();
        for kind in [DenyKind::WrongIp, DenyKind::WrongPort, DenyKind::NotTcp] {
            install_filter_v6(&engine, &app, trusted_addr.port(), kind);
        }
        assert!(connect(trusted_addr).is_ok(), "正确 ::1 代理被误阻断");
        assert!(connect(other_addr).is_err(), "IPv6 上其他代理端口被绕过");
        assert!(!udp_reaches(&udp_server, udp_server.local_addr().unwrap()),
            "IPv6 同 IP 同端口 UDP 仍可送达，非 TCP 出口没有被挡住");
        drop(engine);
        assert!(connect(other_addr).is_ok(), "IPv6 过滤器未随动态会话清理");
        assert!(udp_reaches(&udp_server, udp_server.local_addr().unwrap()),
            "关闭动态会话后 IPv6 UDP 未恢复");
    }

    #[test]
    #[ignore = "仅在隔离的 Windows CI 或临时测试机上显式启用，不影响日常 cargo test"]
    fn proxy_exact_loopback_ip_and_port_are_the_only_allowed_tcp_destination() {
        assert_eq!(std::env::var("SPIDERVPN_WFP_CANARY").as_deref(), Ok("1"),
            "需显式设置 SPIDERVPN_WFP_CANARY=1；不在真实交易机器自动运行");
        let trusted = TcpListener::bind("127.0.0.1:0").expect("允许端点");
        let other = TcpListener::bind("127.0.0.1:0").expect("另一代理端口");
        let trusted_addr = trusted.local_addr().unwrap();
        let other_addr = other.local_addr().unwrap();
        assert!(connect(trusted_addr).is_ok(), "安装 WFP 前，可信端点本来应可用");
        assert!(connect(other_addr).is_ok(), "安装 WFP 前，另一端点本来应可用");
        // TCP 与 UDP 可以在同一个数字端口监听。v2 只允许指定 TCP 代理端点。
        let udp_server = UdpSocket::bind(("127.0.0.1", trusted_addr.port()))
            .expect("在可信 TCP 代理端口旁建立 UDP 负对照");
        assert!(udp_reaches(&udp_server, udp_server.local_addr().unwrap()),
            "安装前 UDP 负对照必须实际送达，否则不能证明它被规则阻断");

        let engine = DynamicEngine::open();
        let app = AppId::this_test_exe();
        for kind in [DenyKind::WrongIp, DenyKind::WrongPort, DenyKind::NotTcp] {
            install_filter(&engine, &app, trusted_addr.port(), kind);
        }

        assert!(connect(trusted_addr).is_ok(),
            "正确本地代理 IP+port+TCP 被误阻断，WFP v2 不能发布");
        assert!(connect(other_addr).is_err(),
            "其他 localhost 端口被放行，WFP v2 会留下绕行通道");
        assert!(!udp_reaches(&udp_server, udp_server.local_addr().unwrap()),
            "同 IP 同端口的 UDP 流量仍可实际送达，IP_PROTOCOL 防绕过失效");

        // BFE 动态会话关闭后，过滤器必须自动全部移除。
        drop(engine);
        assert!(connect(other_addr).is_ok(), "动态规则退出后没有清理");
        assert!(udp_reaches(&udp_server, udp_server.local_addr().unwrap()),
            "关闭动态会话后 UDP 必须恢复，不能留下残余过滤器");
    }
}
