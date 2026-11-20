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
    use windows_sys::Win32::NetworkManagement::{IpHelper as Ip, WindowsFilteringPlatform as W};

    /// 不返回持久句柄：本探针的所有 WFP 对象都归动态会话。
    struct DynamicEngine(HANDLE);

    impl DynamicEngine {
        /// 模拟产品的常规/持久 WFP 基础设施所在会话。
        /// 只在隔离 CI 测试中使用：下方 TemporaryProviderLayout 负责删除所有对象。
        fn open_regular() -> Self {
            let mut handle: HANDLE = null_mut();
            let rc = unsafe { W::FwpmEngineOpen0(null(), 10, null(), null(), &mut handle) };
            assert_eq!(rc, 0, "打开非动态 WFP 基础设施测试会话失败：0x{rc:08X}");
            assert!(!handle.is_null());
            Self(handle)
        }

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
        let _ = install_proxy_permit_in_layer(engine, app, port, W::FWPM_SUBLAYER_UNIVERSAL);
    }

    /// 使用指定子层，验证 NULL provider 临时许可不会进入永久保护
    /// provider 的枚举（即使两条规则在同一个 sublayer 仲裁）。
    fn install_proxy_permit_in_layer(
        engine: &DynamicEngine, app: &AppId, port: u16,
        sublayer: windows_sys::core::GUID,
    ) -> u64 {
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
        raw.subLayerKey = sublayer;
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
        id
    }

    /// 只读发现 Windows 对 127.0.0.1 的最佳接口，作为“真实已知下一跳”探针。
    /// 这不是 Wintun 的身份验证，也不会创建/修改路由。
    fn best_loopback_luid() -> u64 {
        let mut index = 0u32;
        // GetBestInterface IPv4 uses the same bytes as inet_addr() in a DWORD.
        let dst = u32::from_ne_bytes([127, 0, 0, 1]);
        let rc = unsafe { Ip::GetBestInterface(dst, &mut index) };
        assert_eq!(rc, 0, "Windows 无法查询 IPv4 loopback 最佳接口：{rc}");
        assert_ne!(index, 0);
        let mut luid = 0u64;
        let rc = unsafe { Ip::ConvertInterfaceIndexToLuid(
            index, (&mut luid as *mut u64).cast(),
        ) };
        assert_eq!(rc, 0, "Windows loopback interface index 无法转为 LUID：{rc}");
        assert_ne!(luid, 0);
        luid
    }

    /// 在 WFP 上安装 APP_ID && NEXTHOP_INTERFACE == 指定 LUID 的正向 soft PERMIT。
    /// 只有与长期全阻断在同一 sublayer、权重高于 BLOCK 时才可改变许可结果。
    fn install_ephemeral_tun_luid_permit(engine: &DynamicEngine, app: &AppId, luid: u64) {
        let mut luid_value = luid;
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
                fieldKey: W::FWPM_CONDITION_IP_NEXTHOP_INTERFACE,
                matchType: W::FWP_MATCH_EQUAL,
                conditionValue: W::FWP_CONDITION_VALUE0 {
                    r#type: W::FWP_UINT64,
                    Anonymous: W::FWP_CONDITION_VALUE0_0 { uint64: &mut luid_value },
                },
            },
        ];
        let mut name: Vec<u16> = "SpiderVPN temporary positive next-hop permit"
            .encode_utf16().chain(Some(0)).collect();
        let mut raw = W::FWPM_FILTER0::default();
        raw.displayData.name = name.as_mut_ptr();
        raw.layerKey = W::FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        raw.subLayerKey = W::FWPM_SUBLAYER_UNIVERSAL;
        raw.weight = W::FWP_VALUE0 {
            r#type: W::FWP_UINT8,
            Anonymous: W::FWP_VALUE0_0 { uint8: 14 },
        };
        raw.numFilterConditions = conditions.len() as u32;
        raw.filterCondition = conditions.as_mut_ptr();
        raw.action = W::FWPM_ACTION0 {
            r#type: W::FWP_ACTION_PERMIT,
            Anonymous: W::FWPM_ACTION0_0 { filterType: windows_sys::core::GUID::default() },
        };
        raw.flags = 0;
        let mut filter_id = 0u64;
        let rc = unsafe { W::FwpmFilterAdd0(engine.0, &raw, null_mut(), &mut filter_id) };
        assert_eq!(rc, 0, "无法安装临时下一跳正向许可：0x{rc:08X}");
        assert_ne!(filter_id, 0);
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

    /// Windows may select a TCP ephemeral port excluded from UDP binds (WSAEACCES 10013).
    /// Reserve UDP first, then try the *same numeric port* for TCP. A different
    /// UDP port would make the protocol-negative test meaningless: the port rule
    /// would block it even if the IP_PROTOCOL condition were broken.
    fn bind_tcp_udp_same_port(ip: std::net::IpAddr) -> (TcpListener, UdpSocket) {
        let ephemeral = SocketAddr::new(ip, 0);
        let mut last_tcp_error = None;
        for _ in 0..64 {
            let udp = UdpSocket::bind(ephemeral)
                .expect("Windows UDP loopback listener preflight failed");
            let endpoint = SocketAddr::new(ip, udp.local_addr().unwrap().port());
            match TcpListener::bind(endpoint) {
                Ok(tcp) => {
                    assert_eq!(tcp.local_addr().unwrap().port(), udp.local_addr().unwrap().port());
                    return (tcp, udp);
                }
                Err(err) => last_tcp_error = Some((endpoint, err)),
            }
        }
        panic!(
            "64 attempts could not allocate a common loopback TCP/UDP port: {last_tcp_error:?}"
        );
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

    // Isolated BFE fixture: an actual inherited anonymous pipe carries the test
    // cancellation simply as EOF. This is NOT a replacement for the product's
    // authenticated named pipe or the distinct-process protocol regression.
    // It measures real filter teardown while BOTH processes are still alive,
    // even when a real restricted process handle cannot terminate the owner.
    #[test]
    #[ignore = "隔离 Windows BFE 与真实管道撤销专项；CI 显式运行"]
    fn pipe_abandonment_revokes_permit_even_when_terminate_is_denied() {
        use std::io::{Read, Write};
        use std::process::{Command, Stdio};
        use std::time::Instant;
        use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED, GetLastError};
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, TerminateProcess,
        };
        assert_eq!(std::env::var("SPIDERVPN_WFP_CANARY").as_deref(), Ok("1"));

        fn wait_for(mut condition: impl FnMut() -> bool, why: &str) {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !condition() {
                assert!(Instant::now() < deadline, "{why}");
                std::thread::sleep(Duration::from_millis(25));
            }
        }
        fn filter_present(engine: &DynamicEngine, id: u64) -> bool {
            let mut raw: *mut W::FWPM_FILTER0 = null_mut();
            let rc = unsafe { W::FwpmFilterGetById0(engine.0, id, &mut raw) };
            if rc == 0 {
                assert!(!raw.is_null());
                let mut ptr = raw.cast::<core::ffi::c_void>();
                unsafe { W::FwpmFreeMemory0(&mut ptr); }
                true
            } else {
                assert_eq!(rc, windows_sys::Win32::Foundation::FWP_E_FILTER_NOT_FOUND as u32,
                    "filter readback failed for an unexpected reason");
                false
            }
        }

        const CHILD: &str = "SPIDERVPN_WFP_PIPE_CANCEL_CHILD";
        if let Some(dir) = std::env::var_os(CHILD) {
            let dir = std::path::PathBuf::from(dir);
            let port: u16 = std::env::var("SPIDERVPN_WFP_LEASE_PORT").unwrap().parse().unwrap();
            let session = DynamicEngine::open();
            let app = AppId::this_test_exe();
            let permit_id = install_proxy_permit_in_layer(&session, &app, port, W::FWPM_SUBLAYER_UNIVERSAL);
            std::fs::write(dir.join("ready"), permit_id.to_string()).unwrap();
            let input = std::io::stdin();
            let mut input = input.lock();
            let mut byte = [0u8; 1];
            match input.read(&mut byte).unwrap() {
                0 => {}, // abandoned before final Receipt
                1 => {
                    assert_eq!(byte, [b'R']);
                    std::fs::write(dir.join("receipt"), b"consumed").unwrap();
                    assert_eq!(input.read(&mut byte).unwrap(), 0,
                        "test channel must close, not deliver unrelated data");
                }
                _ => unreachable!(),
            }
            drop(session);
            std::fs::write(dir.join("revoked"), b"closed").unwrap();
            // Stay alive after real session close so the outer test can't confuse
            // this assertion with RPC rundown triggered by terminating the owner.
            wait_for(|| dir.join("exit").exists(), "parent did not confirm BFE readback");
            return;
        }

        let allowed = TcpListener::bind("127.0.0.1:0").unwrap();
        let other = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = allowed.local_addr().unwrap();
        let denied = other.local_addr().unwrap();
        let _drain_a = ListenerDrain::start(&allowed);
        let _drain_b = ListenerDrain::start(&other);
        assert!(connect(addr).is_ok() && connect(denied).is_ok());
        let baseline = DynamicEngine::open();
        let audit = DynamicEngine::open_regular();
        let app = AppId::this_test_exe();
        let block_id = install_legacy_block(&baseline, &app);
        assert!(filter_present(&audit, block_id));
        assert!(connect(addr).is_err() && connect(denied).is_err());

        for after_receipt in [false, true] {
            let dir = std::env::temp_dir().join(format!("spidervpn-wfp-cancel-{}-{}-{}",
                std::process::id(), addr.port(), after_receipt));
            std::fs::create_dir(&dir).unwrap();
            let mut child = KillChild(Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact",
                    "windows_canary::pipe_abandonment_revokes_permit_even_when_terminate_is_denied",
                    "--nocapture"])
                .env(CHILD, &dir)
                .env("SPIDERVPN_WFP_LEASE_PORT", addr.port().to_string())
                .stdin(Stdio::piped()).spawn().unwrap());
            let mut writer = child.0.stdin.take().unwrap();
            let mut id = None;
            wait_for(|| {
                assert!(child.0.try_wait().unwrap().is_none(), "helper exited before installing permit");
                id = std::fs::read_to_string(dir.join("ready")).ok().and_then(|s| s.parse::<u64>().ok());
                id.is_some()
            }, "missing dynamic permit ID");
            let permit_id = id.unwrap();
            assert!(filter_present(&audit, permit_id));
            assert!(connect(addr).is_ok() && connect(denied).is_err());
            if after_receipt {
                writer.write_all(b"R").unwrap();
                writer.flush().unwrap();
                wait_for(|| dir.join("receipt").exists(), "child did not consume receipt");
                assert!(filter_present(&audit, permit_id));
                assert!(connect(addr).is_ok());
            }
            let restricted = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, child.0.id()) };
            assert!(!restricted.is_null());
            let killed = unsafe { TerminateProcess(restricted, 1) };
            let error = unsafe { GetLastError() };
            unsafe { CloseHandle(restricted); }
            assert_eq!(killed, 0, "restricted handle unexpectedly had kill rights");
            assert_eq!(error, ERROR_ACCESS_DENIED);
            assert!(child.0.try_wait().unwrap().is_none());
            // Parent remains alive and never kills the helper on the passing path.
            drop(writer);
            wait_for(|| dir.join("revoked").exists(), "channel closure did not revoke the session");
            wait_for(|| !filter_present(&audit, permit_id), "BFE still contains the revoked permit");
            assert!(child.0.try_wait().unwrap().is_none(), "owner exited before readback");
            assert!(filter_present(&audit, block_id), "baseline BLOCK unexpectedly removed");
            assert!(connect(addr).is_err() && connect(denied).is_err());
            std::fs::write(dir.join("exit"), b"done").unwrap();
            wait_for(|| child.0.try_wait().unwrap().is_some(), "worker did not finish");
            assert!(child.0.wait().unwrap().success());
            std::fs::remove_dir_all(dir).unwrap();
        }
        drop(baseline);
        assert!(connect(addr).is_ok() && connect(denied).is_ok());
    }

    #[test]
    #[ignore = "使用真实 Windows loopback 接口 LUID 验证正向 WFP TUN 许可的匹配语义；不创建 TUN"]
    fn positive_next_hop_permit_matches_only_the_actual_loopback_luid() {
        assert_eq!(std::env::var("SPIDERVPN_WFP_CANARY").as_deref(), Ok("1"));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let _drain = ListenerDrain::start(&listener);
        let endpoint = listener.local_addr().unwrap();
        assert!(connect(endpoint).is_ok());
        let baseline = DynamicEngine::open();
        let app = AppId::this_test_exe();
        install_legacy_block(&baseline, &app);
        assert!(connect(endpoint).is_err(), "默认阻断不生效");

        let actual_luid = best_loopback_luid();
        let wrong = DynamicEngine::open();
        install_ephemeral_tun_luid_permit(&wrong, &app, actual_luid ^ 1);
        assert!(connect(endpoint).is_err(),
            "错误下一跳 LUID 的 PERMIT 意外放行，将造成 TUN 直连泄漏");
        drop(wrong);

        let correct = DynamicEngine::open();
        install_ephemeral_tun_luid_permit(&correct, &app, actual_luid);
        assert!(connect(endpoint).is_ok(),
            "正确 loopback LUID 的 PERMIT 不匹配，TUN 方案可能不可用");
        drop(correct);
        assert!(connect(endpoint).is_err(), "动态下一跳许可退出后没有恢复全阻断");
        drop(baseline);
        assert!(connect(endpoint).is_ok(), "规则清理后 loopback 应恢复");
    }

    /// 专用临时 provider 与 sublayer：不能碰用户设备上的 SpiderVPN 正式 GUID。
    fn private_guard_ids(seed: u16) -> (windows_sys::core::GUID, windows_sys::core::GUID) {
        let make = |suffix| windows_sys::core::GUID {
            data1: 0x751A_0000 | (seed as u32), data2: suffix,
            data3: 0x49A0, data4: [0xA1, 0x28, 0x8F, 0x93, 0x11, 0x32, 0x72, 0xC7],
        };
        (make(0x0101), make(0x0202))
    }

    fn create_temp_provider_sublayer(
        engine: &DynamicEngine, provider: &windows_sys::core::GUID,
        sublayer: &windows_sys::core::GUID,
    ) {
        let mut provider_name: Vec<u16> = "SpiderVPN isolated WFP provider test"
            .encode_utf16().chain(Some(0)).collect();
        let mut provider_def = W::FWPM_PROVIDER0::default();
        provider_def.providerKey = *provider;
        provider_def.displayData.name = provider_name.as_mut_ptr();
        let rc = unsafe { W::FwpmProviderAdd0(engine.0, &provider_def, null_mut()) };
        assert_eq!(rc, 0, "动态测试 provider 创建失败：0x{rc:08X}");

        let mut sublayer_name: Vec<u16> = "SpiderVPN isolated WFP sublayer test"
            .encode_utf16().chain(Some(0)).collect();
        let mut owner = *provider;
        let mut sub = W::FWPM_SUBLAYER0::default();
        sub.subLayerKey = *sublayer;
        sub.displayData.name = sublayer_name.as_mut_ptr();
        sub.providerKey = &mut owner;
        sub.weight = 0xFFFF;
        let rc = unsafe { W::FwpmSubLayerAdd0(engine.0, &sub, null_mut()) };
        assert_eq!(rc, 0, "动态测试 sublayer 创建失败：0x{rc:08X}");
    }

    fn install_provider_block(
        engine: &DynamicEngine, app: &AppId,
        provider: &windows_sys::core::GUID, sublayer: &windows_sys::core::GUID,
    ) -> u64 {
        let mut owner = *provider;
        let mut conditions = [W::FWPM_FILTER_CONDITION0 {
            fieldKey: W::FWPM_CONDITION_ALE_APP_ID,
            matchType: W::FWP_MATCH_EQUAL,
            conditionValue: W::FWP_CONDITION_VALUE0 {
                r#type: W::FWP_BYTE_BLOB_TYPE,
                Anonymous: W::FWP_CONDITION_VALUE0_0 { byteBlob: app.0 },
            },
        }];
        let mut name: Vec<u16> = "SpiderVPN isolated provider baseline block"
            .encode_utf16().chain(Some(0)).collect();
        let mut filter = W::FWPM_FILTER0::default();
        filter.displayData.name = name.as_mut_ptr();
        filter.providerKey = &mut owner;
        filter.layerKey = W::FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        filter.subLayerKey = *sublayer;
        filter.weight = W::FWP_VALUE0 {
            r#type: W::FWP_UINT8,
            Anonymous: W::FWP_VALUE0_0 { uint8: 13 },
        };
        filter.numFilterConditions = 1;
        filter.filterCondition = conditions.as_mut_ptr();
        filter.action = W::FWPM_ACTION0 {
            r#type: W::FWP_ACTION_BLOCK,
            Anonymous: W::FWPM_ACTION0_0 { filterType: windows_sys::core::GUID::default() },
        };
        let mut id = 0u64;
        let rc = unsafe { W::FwpmFilterAdd0(engine.0, &filter, null_mut(), &mut id) };
        assert_eq!(rc, 0, "动态测试 provider block 安装失败：0x{rc:08X}");
        assert_ne!(id, 0);
        id
    }

    fn provider_filter_count(engine: &DynamicEngine, provider: &windows_sys::core::GUID) -> usize {
        let mut owner = *provider;
        let mut template = W::FWPM_FILTER_ENUM_TEMPLATE0::default();
        template.providerKey = &mut owner;
        template.layerKey = W::FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        template.actionMask = 0xFFFF_FFFF; // include BLOCK and PERMIT; provider key does the scoping
        let mut handle: HANDLE = null_mut();
        let rc = unsafe { W::FwpmFilterCreateEnumHandle0(engine.0, &template, &mut handle) };
        assert_eq!(rc, 0, "无法枚举隔离测试 provider 规则：0x{rc:08X}");
        let mut total = 0usize;
        loop {
            let mut entries: *mut *mut W::FWPM_FILTER0 = null_mut();
            let mut count = 0u32;
            let rc = unsafe {
                W::FwpmFilterEnum0(engine.0, handle, 32, &mut entries, &mut count)
            };
            assert_eq!(rc, 0, "读取隔离测试 provider 规则失败：0x{rc:08X}");
            total += count as usize;
            if !entries.is_null() {
                let mut mem = entries.cast::<core::ffi::c_void>();
                unsafe { W::FwpmFreeMemory0(&mut mem); }
            }
            if count < 32 { break; }
        }
        let rc = unsafe { W::FwpmFilterDestroyEnumHandle0(engine.0, handle) };
        assert_eq!(rc, 0, "WFP 枚举器关闭失败：0x{rc:08X}");
        total
    }

    /// 非动态基础设施测试必须主动清理所有对象；使用固定作用域 RAII
    /// 即使断言失败也会尝试删除，避免把测试防火墙留给其它任务。
    struct TemporaryProviderLayout<'a> {
        engine: &'a DynamicEngine,
        provider: windows_sys::core::GUID,
        sublayer: windows_sys::core::GUID,
        block_id: u64,
    }
    impl Drop for TemporaryProviderLayout<'_> {
        fn drop(&mut self) {
            let filter_rc = unsafe { W::FwpmFilterDeleteById0(self.engine.0, self.block_id) };
            let sub_rc = unsafe { W::FwpmSubLayerDeleteByKey0(self.engine.0, &self.sublayer) };
            let provider_rc = unsafe { W::FwpmProviderDeleteByKey0(self.engine.0, &self.provider) };
            if filter_rc != 0 || sub_rc != 0 || provider_rc != 0 {
                eprintln!("CI 隔离 WFP 对象清理异常: filter={filter_rc:08X}, sub={sub_rc:08X}, provider={provider_rc:08X}");
            }
        }
    }

    #[test]
    #[ignore = "仅隔离 Windows CI：常规会话的 BLOCK 子层允许独立动态会话临时 PERMIT，且不污染 provider 枚举"]
    fn regular_guard_sublayer_accepts_dynamic_unowned_lease() {
        assert_eq!(std::env::var("SPIDERVPN_WFP_CANARY").as_deref(), Ok("1"));
        let trusted = TcpListener::bind("127.0.0.1:0").unwrap();
        let other = TcpListener::bind("127.0.0.1:0").unwrap();
        let allowed = trusted.local_addr().unwrap();
        let denied = other.local_addr().unwrap();
        let _a = ListenerDrain::start(&trusted);
        let _b = ListenerDrain::start(&other);
        assert!(connect(allowed).is_ok() && connect(denied).is_ok());
        let (provider, sublayer) = private_guard_ids(allowed.port());
        let baseline = DynamicEngine::open_regular();
        create_temp_provider_sublayer(&baseline, &provider, &sublayer);
        let app = AppId::this_test_exe();
        let block_id = install_provider_block(&baseline, &app, &provider, &sublayer);
        let layout = TemporaryProviderLayout { engine: &baseline, provider, sublayer, block_id };
        assert!(connect(allowed).is_err() && connect(denied).is_err());
        assert_eq!(provider_filter_count(&baseline, &provider), 1);

        // 核心差别：临时许可在单独的动态会话，子层在非动态常规会话。
        // 真正的持久 Guard 也是独立于 lease 会话的。
        let permit = DynamicEngine::open();
        let _permit_id = install_proxy_permit_in_layer(&permit, &app, allowed.port(), sublayer);
        assert_eq!(provider_filter_count(&baseline, &provider), 1,
            "临时无 provider 许可不允许污染 v1 持久规则列表");
        assert!(connect(allowed).is_ok(), "独立动态租约无法放行可信代理");
        assert!(connect(denied).is_err(), "临时租约不能绕过其它端口");
        drop(permit);
        assert!(connect(allowed).is_err() && connect(denied).is_err(),
            "动态租约退出后必须恢复基础 BLOCK");
        drop(layout);
        drop(baseline);
        assert!(connect(allowed).is_ok() && connect(denied).is_ok());
    }

    #[test]
    #[ignore = "仅 Windows CI：同一动态会话验证 NULL provider 的过滤器不污染有归属 BLOCK 的枚举"]
    fn dynamic_permit_is_excluded_from_persistent_provider_enumeration() {
        assert_eq!(std::env::var("SPIDERVPN_WFP_CANARY").as_deref(), Ok("1"));
        let trusted = TcpListener::bind("127.0.0.1:0").unwrap();
        let other = TcpListener::bind("127.0.0.1:0").unwrap();
        let trusted_addr = trusted.local_addr().unwrap();
        let other_addr = other.local_addr().unwrap();
        let _drain_a = ListenerDrain::start(&trusted);
        let _drain_b = ListenerDrain::start(&other);
        assert!(connect(trusted_addr).is_ok() && connect(other_addr).is_ok());

        let (provider, sublayer) = private_guard_ids(trusted_addr.port());
        let baseline = DynamicEngine::open();
        create_temp_provider_sublayer(&baseline, &provider, &sublayer);
        let app = AppId::this_test_exe();
        let _ = install_provider_block(&baseline, &app, &provider, &sublayer);
        assert_eq!(provider_filter_count(&baseline, &provider), 1);
        assert!(connect(trusted_addr).is_err() && connect(other_addr).is_err());

        // 这个“隔离 provider”用例刻意在*同一动态会话*中创建子层与许可：
        // Windows 不允许另一动态会话引用前一动态会话拥有的子层
        // (FWP_E_WRONG_SESSION / 0x8032000C)。
        // 真正生产路径是“已有持久子层 + 新动态 lease”，必须另行验证。
        let permit_id = install_proxy_permit_in_layer(
            &baseline, &app, trusted_addr.port(), sublayer,
        );
        assert_eq!(provider_filter_count(&baseline, &provider), 1,
            "临时许可不应被 v1 provider 枚举为多余规则");
        assert!(connect(trusted_addr).is_ok(), "临时许可未在自有 provider 子层中放行可信端点");
        assert!(connect(other_addr).is_err(), "临时许可意外绕开旧 BLOCK");
        delete_filter(&baseline, permit_id);
        assert_eq!(provider_filter_count(&baseline, &provider), 1);
        assert!(connect(trusted_addr).is_err() && connect(other_addr).is_err(),
            "移除临时许可后必须恢复旧全阻断规则的语义");
        drop(baseline);
        assert!(connect(trusted_addr).is_ok() && connect(other_addr).is_ok());
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
        let (trusted, udp_server) = bind_tcp_udp_same_port(
            "::1".parse().expect("valid IPv6 loopback"),
        );
        let other = TcpListener::bind("[::1]:0").expect("IPv6 非白名单端口");
        let trusted_addr = trusted.local_addr().unwrap();
        let other_addr = other.local_addr().unwrap();
        assert_eq!(trusted_addr.port(), udp_server.local_addr().unwrap().port());
        assert!(connect(trusted_addr).is_ok());
        assert!(connect(other_addr).is_ok());
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
        let (trusted, udp_server) = bind_tcp_udp_same_port(
            "127.0.0.1".parse().expect("valid IPv4 loopback"),
        );
        let other = TcpListener::bind("127.0.0.1:0").expect("另一代理端口");
        let trusted_addr = trusted.local_addr().unwrap();
        let other_addr = other.local_addr().unwrap();
        assert_eq!(trusted_addr.port(), udp_server.local_addr().unwrap().port());
        assert!(connect(trusted_addr).is_ok(), "安装 WFP 前，可信端点本来应可用");
        assert!(connect(other_addr).is_ok(), "安装 WFP 前，另一端点本来应可用");
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
