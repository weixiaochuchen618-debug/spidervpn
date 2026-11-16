"""表单夹具：宿主下发的 Form 快照。

形状由 Rust 侧 `src/uiweb_form.rs` 的单测钉住（`rename_form_carries_the_current_name…`、
`line_settings_switches_transport_and_reads_back_the_real_value`）。两边任何一侧改了
字段名或结构，Rust 单测或这里的 Edge 用例必然有一边失败。
"""

FORM_RENAME = {
    "Actions": [],
    "Description": "",
    "Generation": 1,
    "Nodes": [
        {"Kind": "text", "Text": "只改这台电脑上的显示名称；线路 ID、服务器地址、连接记录都不变。", "Tone": "muted"},
        {"Kind": "card", "Children": [
            {"Kind": "text", "Text": "线路名称"},
            {"Id": "name", "Kind": "input", "Label": "线路名称", "MaxLength": 120,
             "Name": "RenameLineName", "Value": "东京 02"},
        ]},
    ],
    "PageActions": [
        {"Disabled": False, "Id": "save-rename", "Kind": "button", "Name": "RenameLineSave",
         "Text": "保存名称", "Tone": "primary"},
        {"Disabled": False, "Id": "back", "Kind": "button", "Name": "RenameLineCancel",
         "Text": "取消", "Tone": "ghost"},
    ],
    "ParentPage": "lines",
    "Title": "重命名线路",
    "ViewKey": "line-rename",
}

FORM_SETTINGS = {
    "Actions": [],
    "Description": "",
    "Generation": 1,
    "Nodes": [
        {"Kind": "card", "Children": [
            {"Kind": "text", "Level": 3, "Text": "线路「香港 01」"},
            {"Kind": "text", "Text": "服务器端点：1.2.3.4:443", "Tone": "muted"},
            {"Kind": "text", "Text": "连接方式"},
            {"Children": [
                {"Id": "method-udp", "Kind": "button", "Name": "method-udp",
                 "Text": "标准（UDP）", "Tone": "primary"},
                {"Id": "method-tcp", "Kind": "button", "Name": "method-tcp",
                 "Text": "兼容（TCP）", "Tone": "ghost"},
            ], "Kind": "row"},
            {"Kind": "text", "Text": "标准走 UDP，速率更好；兼容走 TCP，适合 UDP 被限制的网络。切换只影响下次连接，当前连接保持。", "Tone": "muted"},
            {"Kind": "text", "Text": "本页只覆盖连接方式。服务器、邀请与端口改动在后续版本开放。", "Tone": "muted"},
        ]},
    ],
    "PageActions": [
        {"Disabled": False, "Id": "back", "Kind": "button", "Name": "PageBack",
         "Text": "返回", "Tone": "ghost"},
    ],
    "ParentPage": "lines",
    "Title": "连接方式与网络",
    "ViewKey": "line-settings",
}

FORM_HISTORY = {
    "Actions": [],
    "Description": "",
    "Generation": 2,
    "Nodes": [{"Kind": "card", "Children": [
        {"Kind": "text", "Text": "只记录这台电脑上的连接、配置与维护动作；按时间倒序，最新 200 条。", "Tone": "muted"},
        {"Kind": "row", "Children": [
            {"Disabled": False, "Id": "filter-all", "Kind": "button", "Name": "filter-all", "Text": "全部", "Tone": "primary"},
            {"Disabled": False, "Id": "filter-fail", "Kind": "button", "Name": "filter-fail", "Text": "只看失败", "Tone": "ghost"},
        ]},
        {"Kind": "text", "Text": "11-02 02:00 · 连接 · 成功 · 线路（ui）"},
        {"Kind": "text", "Text": "11-02 01:59 · 导入 · 失败 · 端口被占用（cli）"},
    ]}],
    "PageActions": [
        {"Disabled": False, "Id": "export-history", "Kind": "button", "Name": "ExportHistory",
         "Text": "导出当前筛选", "Tone": "primary"},
        {"Disabled": False, "Id": "back", "Kind": "button", "Name": "PageBack", "Text": "返回", "Tone": "ghost"},
    ],
    "ParentPage": "settings",
    "Title": "操作记录",
    "ViewKey": "history",
}

FORM_DIAGNOSE = {
    "Actions": [],
    "Description": "",
    "Generation": 3,
    "Nodes": [{"Kind": "card", "Children": [
        {"Kind": "text", "Text": "线路端点可达", "Tone": "muted"},
        {"Kind": "text", "Text": "TCP 1.2.3.4:443  可建立连接，耗时 5 ms"},
    ]}],
    "PageActions": [
        {"Disabled": False, "Id": "run-diagnose", "Kind": "button", "Name": "RunDiagnose",
         "Text": "重新诊断", "Tone": "primary"},
        {"Disabled": False, "Id": "back", "Kind": "button", "Name": "PageBack", "Text": "返回", "Tone": "ghost"},
    ],
    "ParentPage": "settings",
    "Title": "运行诊断",
    "ViewKey": "diagnose",
}

FORM_MAINTENANCE = {
    "Actions": [],
    "Description": "",
    "Generation": 4,
    "Nodes": [{"Kind": "card", "Children": [
        {"Kind": "text", "Text": "上次连接留下了还原凭据：可以把系统代理改回去。"},
        {"Kind": "text", "Text": "凭据记录的原值：127.0.0.1:9545", "Tone": "muted"},
        {"Kind": "text", "Text": "还原只改系统代理并清理凭据，不改线路配置、不联网。", "Tone": "muted"},
        {"Kind": "text", "Text": "「解除交易保护」只在准备停用本工具时使用；日常断开连接无需解除。", "Tone": "muted"},
    ]}],
    "PageActions": [
        {"Disabled": False, "Id": "restore-proxy", "Kind": "button", "Name": "RestoreProxy",
         "Text": "还原系统代理", "Tone": "primary"},
        {"Disabled": False, "Id": "guard-remove", "Kind": "button", "Name": "RemoveGuard",
         "Text": "解除交易保护", "Tone": "danger"},
        {"Disabled": False, "Id": "back", "Kind": "button", "Name": "PageBack", "Text": "返回", "Tone": "ghost"},
    ],
    "ParentPage": "settings",
    "Title": "维护与恢复",
    "ViewKey": "maintenance",
}

FORM_PROVIDERS = {
    "Actions": [],
    "Description": "",
    "Generation": 5,
    "Nodes": [{"Kind": "card", "Children": [
        {"Kind": "text", "Text": "接入本机的代理软件后，日常上网走它自己的出口；成交仍然走线路。", "Tone": "muted"},
        {"Kind": "text", "Text": "槽位 1 · 我的代理 · 日常端口 7890"},
        {"Kind": "text", "Text": "已登记，等待生效（需要重新连接一次）", "Tone": "muted"},
        {"Kind": "row", "Children": [
            {"Disabled": False, "Id": "remove-1", "Kind": "button", "Name": "RemoveProvider",
             "Text": "删除", "Tone": "ghost"},
        ]},
        {"Kind": "rule"},
        {"Kind": "text", "Text": "添加代理软件"},
        {"Disabled": False, "Id": "kind", "Items": [{"Index": 0, "Label": "Clash Verge"}, {"Index": 1, "Label": "BatVPN"}],
         "Kind": "select", "Label": "种类", "Name": "ProviderKind", "Value": 0},
        {"Id": "name", "Kind": "input", "Label": "名称", "MaxLength": 60, "Name": "ProviderName", "Value": "我的代理"},
        {"Id": "port", "Kind": "input", "Label": "日常端口", "MaxLength": 5, "Name": "ProviderPort", "Value": "7890"},
        {"Id": "domains", "Kind": "input", "Label": "引导域名（逗号或换行分隔）", "MaxLength": 4096,
         "Multiline": True, "Name": "ProviderDomains", "Value": "a.com，b.com"},
        {"Kind": "row", "Children": [
            {"Disabled": False, "Id": "discover", "Kind": "button", "Name": "DiscoverProvider",
             "Text": "扫描本机", "Tone": "ghost"},
            {"Disabled": False, "Id": "add-provider", "Kind": "button", "Name": "AddProvider",
             "Text": "添加", "Tone": "primary"},
        ]},
    ]}],
    "PageActions": [
        {"Disabled": False, "Id": "back", "Kind": "button", "Name": "PageBack", "Text": "返回", "Tone": "ghost"},
    ],
    "ParentPage": "lines",
    "Title": "代理软件",
    "ViewKey": "providers",
}

FORM_SPLIT = {
    "Actions": [],
    "Description": "",
    "Generation": 6,
    "Nodes": [
        {"Kind": "card", "Children": [
            {"Kind": "text", "Level": 2, "Text": "程序"},
            {"Kind": "text", "Text": "程序的全部连接使用交易线路；断开时阻止它直接联网。", "Tone": "muted"},
            {"Kind": "row", "Children": [
                {"Kind": "panel", "Children": [
                    {"Kind": "text", "Text": "TradingApp.exe · 已生效"},
                    {"Kind": "text", "Text": "C:\\Apps\\TradingApp.exe", "Tone": "muted"},
                ]},
                {"Align": "end", "Disabled": False, "Id": "remove-process-0", "Kind": "button",
                 "Name": "RemoveSplit", "Text": "移除", "Tone": "ghost"},
            ]},
            {"Kind": "grid", "Columns": 3, "Cols": ["*", "Auto", "Auto"], "Children": [
                {"Id": "program-path", "Kind": "input", "Label": "把程序文件拖到这里，或点「浏览…」",
                 "MaxLength": 1024, "Name": "TradeProgramInput", "Value": ""},
                {"Disabled": False, "Id": "pick-program", "Kind": "button",
                 "Name": "BrowseTradeProgram", "Text": "浏览…", "Tone": "ghost"},
                {"Disabled": False, "Id": "add-program", "Kind": "button",
                 "Name": "AddTradeProgram", "Text": "添加程序", "Tone": "primary"},
            ]},
        ]},
        {"Kind": "card", "Children": [
            {"Kind": "text", "Level": 2, "Text": "交易网站"},
            {"Kind": "text", "Text": "只调整这些网站的线路，不会限制整个浏览器。", "Tone": "muted"},
            {"Kind": "row", "Children": [
                {"Kind": "text", "Text": "example.com"},
                {"Align": "end", "Disabled": False, "Id": "remove-domain-0", "Kind": "button",
                 "Name": "RemoveSplit", "Text": "移除", "Tone": "ghost"},
            ]},
            {"Kind": "grid", "Columns": 2, "Cols": ["*", "Auto"], "Children": [
                {"Id": "site-domain", "Kind": "input", "Label": "填写网址或域名，子域名会一并加入",
                 "MaxLength": 1024, "Name": "TradeDomainInput", "Value": ""},
                {"Disabled": False, "Id": "add-site", "Kind": "button",
                 "Name": "AddTradeDomain", "Text": "添加网站", "Tone": "primary"},
            ]},
            {"Disabled": False, "Id": "reset-trade-domains", "Kind": "button",
             "Name": "ResetTradeDomains", "Text": "恢复默认网站", "Tone": "ghost"},
        ]},
    ],
    "PageActions": [
        {"Disabled": False, "Id": "back", "Kind": "button", "Name": "PageBack", "Text": "返回", "Tone": "ghost"},
    ],
    "ParentPage": "apps",
    "Title": "交易软件名单",
    "ViewKey": "split",
}


# ---------------------------------------------------------------------------
# 「自己搭服务器」：四步快照。
#
# 直接从 `FormState::render_deploy()` 的真实输出导出（`dump_deploy_forms_for_fixtures`），
# 所以这里验的是「这份 app.js 认不认这套节点」，不是「宿主有没有按预期写」。
# 宿主侧的形状由 Rust 单测（`the_self_hosted_deploy_form_walks_from_address_to_finished`）钉住。
# ---------------------------------------------------------------------------

FORM_DEPLOY_ADDRESS = {
    "Actions": [],
    "Description": "",
    "Generation": 1,
    "Nodes": [{"Kind": "card", "Children": [
        {"Kind": "text", "Tone": "muted",
         "Text": "需要一台能用 SSH 登录的 Linux 云服务器（Ubuntu / Debian）。"
                 "本机会自动装好服务端、配好兼容连接，并把线路登记到这台电脑。"},
        {"Id": "spec", "Kind": "input", "Label": "服务器地址", "MaxLength": 200,
         "Name": "DeploySpec", "Value": ""},
        {"Kind": "text", "Tone": "muted",
         "Text": "写成 用户名@主机，例如 root@203.0.113.10；端口不是 22 时写 root@主机:2222。"},
        {"Kind": "row", "Children": [
            {"Disabled": False, "Id": "probe", "Kind": "button", "Name": "DeployProbe",
             "Text": "读取指纹并继续", "Tone": "primary"},
        ]},
    ]}],
    # 部署表单不挂 PageActions：返回由面包屑按 ParentPage 生成，
    # 再挂一个会被渲染成页面下方一块空白卡片。
    "PageActions": [],
    "ParentPage": "home",
    "Title": "自己搭服务器",
    "ViewKey": "server-deploy",
}

FORM_DEPLOY_VERIFY = {
    "Actions": [],
    "Description": "",
    "Generation": 2,
    "Nodes": [{"Kind": "card", "Children": [
        {"Kind": "text", "Text": "服务器身份", "Tone": "muted"},
        {"Kind": "text", "Text": "SHA256:ehkYyHsNGRNWevQ99M116zpp3ExT9B9GdN3pUUdr4kI", "Tone": "muted"},
        {"Kind": "text", "Tone": "muted",
         "Text": "请与服务器管理员核对这串指纹。确认之后才会发送密码——"
                 "指纹不对时，密码一个字节都不会离开这台电脑。"},
        {"Id": "password", "Kind": "password", "Label": "登录密码", "MaxLength": 200,
         "Name": "DeployPassword", "SecretPresent": False},
        {"Kind": "text", "Tone": "muted",
         "Text": "密码只用于这次登录，之后封存在本机，不会写进任何日志。"},
        {"Kind": "row", "Children": [
            {"Disabled": False, "Id": "start", "Kind": "button", "Name": "DeployStart",
             "Text": "开始部署", "Tone": "primary"},
            {"Disabled": False, "Id": "deploy-back", "Kind": "button", "Name": "DeployBack",
             "Text": "上一步", "Tone": "ghost"},
        ]},
    ]}],
    # 部署表单不挂 PageActions：返回由面包屑按 ParentPage 生成，
    # 再挂一个会被渲染成页面下方一块空白卡片。
    "PageActions": [],
    "ParentPage": "home",
    "Title": "自己搭服务器",
    "ViewKey": "server-deploy",
}

FORM_DEPLOY_DONE = {
    "Actions": [],
    "Description": "",
    "Generation": 5,
    "Nodes": [{"Kind": "card", "Children": [
        {"Kind": "text", "Text": "部署完成。", "Tone": "muted"},
        {"Kind": "text", "Tone": "muted",
         "Text": "服务器：root@203.0.113.10:22（接口 tc32d4f356，UDP 51820）"},
        {"Kind": "text", "Tone": "muted",
         "Text": "兼容连接：TCP 8443（REALITY，握手域名 www.bing.com）"},
        {"Kind": "text", "Tone": "muted",
         "Text": "自建 · 203.0.113.10（127.0.0.1:17890，标准连接）"},
        {"Kind": "text", "Tone": "muted",
         "Text": "自建 · 203.0.113.10（兼容连接）（127.0.0.1:17891，兼容连接）"},
        {"Kind": "text", "Text": "下一步：回到首页连接这条线路。", "Tone": "muted"},
        {"Kind": "row", "Children": [
            {"Disabled": False, "Id": "done", "Kind": "button", "Name": "DeployDone",
             "Text": "完成", "Tone": "primary"},
        ]},
    ]}],
    # 部署表单不挂 PageActions：返回由面包屑按 ParentPage 生成，
    # 再挂一个会被渲染成页面下方一块空白卡片。
    "PageActions": [],
    "ParentPage": "home",
    "Title": "自己搭服务器",
    "ViewKey": "server-deploy",
}

FORM_DEPLOY_FAILED = {
    "Actions": [],
    "Description": "",
    "Generation": 6,
    "Nodes": [{"Kind": "card", "Children": [
        {"Kind": "text", "Text": "没有完成。", "Tone": "warn"},
        {"Kind": "text", "Text": "这台服务器不能部署：需要 root 权限。", "Tone": "muted"},
        {"Kind": "text", "Text": "[1/4] 检查 …", "Tone": "muted"},
        {"Kind": "text", "Text": "[3/4] 安装兼容连接 …", "Tone": "muted"},
        {"Kind": "row", "Children": [
            {"Disabled": False, "Id": "retry", "Kind": "button", "Name": "DeployRetry",
             "Text": "重新开始", "Tone": "primary"},
            {"Disabled": False, "Id": "done", "Kind": "button", "Name": "DeployDone",
             "Text": "关闭", "Tone": "ghost"},
        ]},
    ]}],
    # 部署表单不挂 PageActions：返回由面包屑按 ParentPage 生成，
    # 再挂一个会被渲染成页面下方一块空白卡片。
    "PageActions": [],
    "ParentPage": "home",
    "Title": "自己搭服务器",
    "ViewKey": "server-deploy",
}


# ---------------------------------------------------------------------------
# 「服务器与设备」：四态快照。
#
# 与部署表单同一条规矩：直接从 `FormState::render_devices()` 的真实输出导出，
# 验的是「这份 app.js 认不认这套节点」。宿主形状由 `uiweb.rs` 的两条单测钉住。
# ---------------------------------------------------------------------------

# 还在读服务器：只给一句「正在读取」，不许先画一张空表。
FORM_DEVICES_LOADING = {
    "Actions": [],
    "Description": "",
    "Generation": 1,
    "Nodes": [
        {
            "Children": [
                {
                    "Kind": "text",
                    "Text": "正在读取服务器与设备…",
                    "Tone": "muted"
                },
                {
                    "Kind": "text",
                    "Text": "这一步只读：不改服务器、不动当前连接。",
                    "Tone": "muted"
                }
            ],
            "Kind": "card"
        }
    ],
    "PageActions": [],
    "ParentPage": "lines",
    "Title": "服务器与设备",
    "ViewKey": "server-devices"
}

# 隧道在跑、两台设备（其中一台是本机）。
FORM_DEVICES_READY = {
    "Actions": [],
    "Description": "",
    "Generation": 2,
    "Nodes": [
        {
            "Children": [
                {
                    "Kind": "text",
                    "Level": 3,
                    "Text": "自建 · 203.0.113.10"
                },
                {
                    "Kind": "text",
                    "Text": "服务器：root@203.0.113.10:22（接口 tc32d4f356，UDP 51820，网段 10.66.0.0/24）",
                    "Tone": "muted"
                },
                {
                    "Kind": "text",
                    "Text": "主机指纹：SHA256:ehkYyHsNGRNWevQ99M116zpp3ExT9B9GdN3pUUdr4kI",
                    "Tone": "muted"
                },
                {
                    "Kind": "text",
                    "Text": "隧道：运行中，2 小时前，合计收 4.50 GB / 发 300.0 MB",
                    "Tone": "muted"
                },
                {
                    "Kind": "rule"
                },
                {
                    "Kind": "text",
                    "Text": "已登记的设备（2 台）",
                    "Tone": "muted"
                },
                {
                    "Kind": "text",
                    "Text": "设备 10.66.0.2（本机）",
                    "Tone": "muted"
                },
                {
                    "Kind": "text",
                    "Text": "  uYq3P0kL… · 2 小时前 · 收 4.50 GB / 发 300.0 MB，对端 203.0.113.77:52894",
                    "Tone": "muted"
                },
                {
                    "Kind": "text",
                    "Text": "设备 10.66.0.3",
                    "Tone": "muted"
                },
                {
                    "Kind": "text",
                    "Text": "  AbCdEfGh… · 从未握手 · 收 0 B / 发 0 B",
                    "Tone": "muted"
                },
                {
                    "Children": [
                        {
                            "Disabled": False,
                            "Id": "revoke-1",
                            "Kind": "button",
                            "Name": "RevokeDevice",
                            "Text": "移除",
                            "Tone": "ghost"
                        }
                    ],
                    "Kind": "row"
                },
                {
                    "Children": [
                        {
                            "Disabled": False,
                            "Id": "refresh",
                            "Kind": "button",
                            "Name": "DevicesRefresh",
                            "Text": "刷新",
                            "Tone": "ghost"
                        }
                    ],
                    "Kind": "row"
                }
            ],
            "Kind": "card"
        }
    ],
    "PageActions": [],
    "ParentPage": "lines",
    "Title": "服务器与设备",
    "ViewKey": "server-devices"
}

# 点过「移除」之后：确认层（撤销不可逆，先问一次）。
FORM_DEVICES_CONFIRM = {
    "Actions": [],
    "Description": "",
    "Generation": 3,
    "Nodes": [
        {
            "Children": [
                {
                    "Kind": "text",
                    "Level": 3,
                    "Text": "自建 · 203.0.113.10"
                },
                {
                    "Kind": "text",
                    "Text": "服务器：root@203.0.113.10:22（接口 tc32d4f356，UDP 51820，网段 10.66.0.0/24）",
                    "Tone": "muted"
                },
                {
                    "Kind": "text",
                    "Text": "主机指纹：SHA256:ehkYyHsNGRNWevQ99M116zpp3ExT9B9GdN3pUUdr4kI",
                    "Tone": "muted"
                },
                {
                    "Kind": "text",
                    "Text": "隧道：运行中，2 小时前，合计收 4.50 GB / 发 300.0 MB",
                    "Tone": "muted"
                },
                {
                    "Kind": "rule"
                },
                {
                    "Kind": "text",
                    "Text": "确定移除设备 10.66.0.3 吗？",
                    "Tone": "warn"
                },
                {
                    "Kind": "text",
                    "Text": "它会立刻失去访问权，要重新加入才能恢复。这台电脑与其它设备不受影响。",
                    "Tone": "muted"
                },
                {
                    "Children": [
                        {
                            "Disabled": False,
                            "Id": "revoke-confirm",
                            "Kind": "button",
                            "Name": "RevokeConfirm",
                            "Text": "确认移除",
                            "Tone": "danger"
                        },
                        {
                            "Disabled": False,
                            "Id": "revoke-cancel",
                            "Kind": "button",
                            "Name": "RevokeCancel",
                            "Text": "取消",
                            "Tone": "ghost"
                        }
                    ],
                    "Kind": "row"
                },
                {
                    "Kind": "rule"
                },
                {
                    "Kind": "text",
                    "Text": "已登记的设备（2 台）",
                    "Tone": "muted"
                },
                {
                    "Kind": "text",
                    "Text": "设备 10.66.0.2（本机）",
                    "Tone": "muted"
                },
                {
                    "Kind": "text",
                    "Text": "  uYq3P0kL… · 2 小时前 · 收 4.50 GB / 发 300.0 MB，对端 203.0.113.77:52894",
                    "Tone": "muted"
                },
                {
                    "Kind": "text",
                    "Text": "设备 10.66.0.3",
                    "Tone": "muted"
                },
                {
                    "Kind": "text",
                    "Text": "  AbCdEfGh… · 从未握手 · 收 0 B / 发 0 B",
                    "Tone": "muted"
                },
                {
                    "Children": [
                        {
                            "Disabled": False,
                            "Id": "refresh",
                            "Kind": "button",
                            "Name": "DevicesRefresh",
                            "Text": "刷新",
                            "Tone": "ghost"
                        }
                    ],
                    "Kind": "row"
                }
            ],
            "Kind": "card"
        }
    ],
    "PageActions": [],
    "ParentPage": "lines",
    "Title": "服务器与设备",
    "ViewKey": "server-devices"
}


# 接口不存在：设备清单读不到，文案不能写成「一台都没有」。
FORM_DEVICES_DOWN = {
    "Actions": [],
    "Description": "",
    "Generation": 2,
    "Nodes": [
        {
            "Children": [
                {
                    "Kind": "text",
                    "Level": 3,
                    "Text": "自建 · 203.0.113.10"
                },
                {
                    "Kind": "text",
                    "Text": "服务器：root@203.0.113.10:22（接口 tc32d4f356，UDP 51820，网段 10.66.0.0/24）",
                    "Tone": "muted"
                },
                {
                    "Kind": "text",
                    "Text": "主机指纹：SHA256:ehkYyHsNGRNWevQ99M116zpp3ExT9B9GdN3pUUdr4kI",
                    "Tone": "muted"
                },
                {
                    "Kind": "text",
                    "Text": "隧道：接口不存在（服务没起来）。",
                    "Tone": "warn"
                },
                {
                    "Kind": "rule"
                },
                {
                    "Kind": "text",
                    "Text": "服务没起来，读不到设备清单。",
                    "Tone": "muted"
                },
                {
                    "Children": [
                        {
                            "Disabled": False,
                            "Id": "refresh",
                            "Kind": "button",
                            "Name": "DevicesRefresh",
                            "Text": "刷新",
                            "Tone": "ghost"
                        }
                    ],
                    "Kind": "row"
                }
            ],
            "Kind": "card"
        }
    ],
    "PageActions": [],
    "ParentPage": "lines",
    "Title": "服务器与设备",
    "ViewKey": "server-devices"
}

# 读失败：错误原文留在页面，给一个「重新读取」。
FORM_DEVICES_ERROR = {
    "Actions": [],
    "Description": "",
    "Generation": 2,
    "Nodes": [
        {
            "Children": [
                {
                    "Kind": "text",
                    "Text": "读不到设备列表。",
                    "Tone": "warn"
                },
                {
                    "Kind": "text",
                    "Text": "这条线路不是本机部署的服务器线路（找不到对应的服务器记录）。",
                    "Tone": "muted"
                },
                {
                    "Children": [
                        {
                            "Disabled": False,
                            "Id": "refresh",
                            "Kind": "button",
                            "Name": "DevicesRefresh",
                            "Text": "重新读取",
                            "Tone": "primary"
                        }
                    ],
                    "Kind": "row"
                }
            ],
            "Kind": "card"
        }
    ],
    "PageActions": [],
    "ParentPage": "lines",
    "Title": "服务器与设备",
    "ViewKey": "server-devices"
}



# ---------------------------------------------------------------------------
# 「AI 工具名单」的五份快照（FORM_AGENTS_EMPTY / FILLED / BUSY / NO_EXIT /
# OVERRIDE）在 r103 已**删除**，不是搬走。
#
# 它们其实是 r102 之前 `FormState::render_agents()` 的一次性快照：条目是
# `Kind:"check"` 的勾选框、页内还有一台「走向」下拉和一堆 `rule`、域名在正文里
# 写成一行「包含的网站」。r103 的宿主不再下发任何一种这样的节点（一行一颗
# 「添加/移除」按钮、域名挂在名称文本的 `Hint` 上、页内没有走向下拉），文件头那句
# 「直接从 render_agents() 的真实输出导出」早就不成立了。
#
# 更要紧的是：`tests/m1_page_behaviors.py::scenario_agents` 拿它们断言的是**产品形状**
# （「22 个内置项都渲染成复选框」「正文里有包含的网站」），不是「app.js 能不能渲染某类
# 节点」。喂一份冻结的旧载荷只会得到两种结果：改断言就永远是绿的假绿，不改就永远是红——
# 两种都不能证明今天的产品是对的。
#
# 覆盖现在在真机上，而且更严：`tests/r103_agents_rows.py` 启动真实宿主 + WebView2，
# 断言 22 行按钮的文案、点一下不发命令、保存只发一条 `agents-save`、`config.json`
# 真的落盘、域名在 ⓘ 里且悬停才展开、「放弃修改」还原。想再造前端快照夹具，请从**当次
# 构建的宿主**导出（报告里 `agents-form-from-host.json` 就是这种导出），并写明导出的
# 构建 sha256；不要手抄，也不要沿用这一份。
# ---------------------------------------------------------------------------
