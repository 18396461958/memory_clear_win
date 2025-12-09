use std::{
    env,
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use glob::glob;
use windows::{
    core::Result, // 移除未使用的 HSTRING
    Win32::{
        Foundation::{CloseHandle, GetLastError, HANDLE},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, PROCESSENTRY32, Process32First, Process32Next,
                TH32CS_SNAPPROCESS,
            },
            Memory::{
                GetProcessHeap, HEAP_NO_SERIALIZE, HeapCompact, SetProcessWorkingSetSizeEx,
                SETPROCESSWORKINGSETSIZEEX_FLAGS,
            },
            Threading::{
                GetCurrentProcess, GetCurrentProcessId, OpenProcess, PROCESS_QUERY_INFORMATION,
                PROCESS_TERMINATE, PROCESS_VM_OPERATION, TerminateProcess, // 补全导入
            }
        },
    },
};

// ===================== 配置常量（集中管理，便于修改） =====================
/// 系统关键进程白名单（防止误杀）
const PROTECTED_PROCESSES: &[&str] = &[
    // 系统核心进程
    "System", "svchost.exe", "wininit.exe", "csrss.exe", "lsass.exe", "winlogon.exe",
    "services.exe", "smss.exe", "lsaiso.exe", "fontdrvhost.exe","Code.exe",
    // 常用工具
    "msedge.exe", "firefox.exe", "Weixin.exe", "WeChatAppEx.exe", "WeChat.exe",
    "WeChatWeb.exe", "QQ.exe", "DingTalk.exe", "Steam++.exe", "Steam++.Accelerator.exe",
    "conhost.exe", "cmd.exe", "powershell.exe", "rust-analyzer.exe", "rust-analyzer-proc-macro-srv.exe",
];

/// 清理文件的时间阈值（天）
const TEMP_FILE_AGE_DAYS: u64 = 7;
const CACHE_FILE_AGE_DAYS: u64 = 30;
const LOG_FILE_AGE_DAYS: u64 = 90;

/// 当前进程ID（避免自终止）
static mut CURRENT_PID: u32 = 0;

// ===================== 工具函数 =====================
/// RAII 封装 Windows 句柄，自动释放
struct SafeHandle(HANDLE);
impl Drop for SafeHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0).ok(); }
    }
}



/// 正确解码 Windows 宽字符进程名（修复 PCWSTR 类型错误）
/// 解码进程名称
fn decode_process_name(entry: &PROCESSENTRY32) -> String {
    entry.szExeFile
        .iter()
        .take_while(|&&c| c != 0) // 遇到空字符停止
        .map(|&c| c as u8 as char)
        .collect::<String>()
}

/// 判断进程是否在白名单中
fn is_protected(process_name: &str) -> bool {
    let name = process_name.to_lowercase();
    PROTECTED_PROCESSES.iter().any(|&protected| {
        let protected_lc = protected.to_lowercase();
        name == protected_lc || (protected_lc == "chrome.exe" && name.starts_with("chrome.exe"))
    })
}

/// 获取当前用户目录（替代硬编码）
fn get_user_dir() -> PathBuf {
    env::var("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(format!("C:\\Users\\{}", whoami::username())))
}

/// 通用文件清理（基于 glob 通配符）
fn clean_files_glob(pattern: &str) {
    for entry in glob(pattern).expect("无效的文件匹配模式") {
        match entry {
            Ok(path) => {
                if path.is_file() {
                    if let Err(e) = fs::remove_file(&path) {
                        eprintln!("删除文件失败: {} - {}", path.display(), e);
                    }
                } else if path.is_dir() {
                    if let Err(e) = fs::remove_dir_all(&path) {
                        eprintln!("删除目录失败: {} - {}", path.display(), e);
                    }
                }
            }
            Err(e) => eprintln!("匹配文件失败: {}", e),
        }
    }
}

// ===================== 核心功能函数 =====================
/// 终止非关键进程（安全增强版）
fn terminate_non_critical_processes() -> Result<()> {
    unsafe {
        CURRENT_PID = GetCurrentProcessId(); // 获取当前进程ID，避免自杀
    }

    // 创建进程快照（RAII 封装，自动释放）
    let snapshot = SafeHandle(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)? });
    let mut entry: PROCESSENTRY32 = PROCESSENTRY32::default();
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

    unsafe {
        if Process32First(snapshot.0, &mut entry).is_ok() {
            loop {
                let pid = entry.th32ProcessID;
                let process_name = decode_process_name(&entry);

                // 安全过滤：跳过系统核心PID、当前进程、白名单进程
                if pid == 0 || pid == 4 || pid == CURRENT_PID || is_protected(&process_name) {
                    if Process32Next(snapshot.0, &mut entry).is_err() {
                        break;
                    }
                    continue;
                }

                // 尝试终止进程（带权限检查和日志）
                match OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, false, pid) {
                    Ok(handle) => {
                        let handle = SafeHandle(handle); // RAII 封装
                        if TerminateProcess(handle.0, 1).is_ok() {
                            println!("已终止进程: {} (PID: {})", process_name, pid);
                        } else {
                            eprintln!(
                                "终止进程失败: {} (PID: {}) - 错误码: {:?}",
                                process_name, pid, GetLastError()
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "打开进程句柄失败: {} (PID: {}) - {}",
                            process_name, pid, e
                        );
                    }
                }

                if Process32Next(snapshot.0, &mut entry).is_err() {
                    break;
                }
            }
        }
    }

    Ok(())
}

/// 压缩系统内存（清理工作集+堆）
fn compact_system_memory() -> Result<()> {
    unsafe {
        // 压缩当前进程堆
        let heap = GetProcessHeap()?;
        HeapCompact(heap, HEAP_NO_SERIALIZE);

        // 重置当前进程工作集（释放未使用内存）
        let current_process = GetCurrentProcess();
        SetProcessWorkingSetSizeEx(
            current_process,
            !0, // 最小工作集（特殊值：使用系统默认最小值）
            !0, // 最大工作集（特殊值：使用系统默认最大值）
            SETPROCESSWORKINGSETSIZEEX_FLAGS(0),
        )?;

        println!("内存工作集已重置");
    }
    Ok(())
}

/// 清理进程虚拟内存（修复原逻辑漏洞）
fn clear_virtual_memory() -> Result<()> {
    unsafe {
        let snapshot = SafeHandle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?);
        let mut entry: PROCESSENTRY32 = PROCESSENTRY32::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snapshot.0, &mut entry).is_ok() {
            loop {
                let pid = entry.th32ProcessID;
                let process_name = decode_process_name(&entry);

                // 仅清理非保护进程，跳过系统核心PID和当前进程
                if !is_protected(&process_name) && pid != 0 && pid != 4 && pid != CURRENT_PID {
                    // 打开进程（需要VM操作权限）
                    match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION, false, pid) {
                        Ok(handle) => {
                            let handle = SafeHandle(handle);
                            // 清理该进程的工作集（核心逻辑：原代码仅CloseHandle无实际操作）
                            let result = SetProcessWorkingSetSizeEx(
                                handle.0,
                                !0,
                                !0,
                                SETPROCESSWORKINGSETSIZEEX_FLAGS(0),
                            );
                            if result.is_err() {
                                eprintln!(
                                    "清理进程虚拟内存失败: {} (PID: {}) - {:?}",
                                    process_name, pid, GetLastError()
                                );
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "打开进程失败（清理虚拟内存）: {} (PID: {}) - {}",
                                process_name, pid, e
                            );
                        }
                    }
                }

                if Process32Next(snapshot.0, &mut entry).is_err() {
                    break;
                }
            }
        }
    }

    println!("非保护进程虚拟内存已清理");
    Ok(())
}

/// 动态调整CPU时钟（优化错误处理）
fn dynamic_clock_boost(enable: bool) {
    unsafe {
        use windows::Win32::System::Threading::{
            PROCESS_INFORMATION_CLASS, PROCESS_POWER_THROTTLING_STATE, SetProcessInformation,
        };

        // 正确定义 ProcessPowerThrottling 枚举值（避免魔法数字）
        const PROCESS_POWER_THROTTLING: PROCESS_INFORMATION_CLASS = PROCESS_INFORMATION_CLASS(0x12);
        const PROCESS_POWER_THROTTLING_EXECUTION_SPEED: u32 = 0x00000001;
        const PROCESS_POWER_THROTTLING_CURRENT_VERSION: u32 = 1;

        let mut throttling_state = PROCESS_POWER_THROTTLING_STATE {
            Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
            ControlMask: if enable { PROCESS_POWER_THROTTLING_EXECUTION_SPEED } else { 0 },
            StateMask: if enable { PROCESS_POWER_THROTTLING_EXECUTION_SPEED } else { 0 },
        };

        let result = SetProcessInformation(
            GetCurrentProcess(),
            PROCESS_POWER_THROTTLING,
            &mut throttling_state as *mut _ as _,
            std::mem::size_of::<PROCESS_POWER_THROTTLING_STATE>() as u32,
        );

        match result {
            Ok(_) => println!("CPU时钟调整成功（加速: {}）", enable),
            Err(_) => eprintln!(
                "CPU时钟调整失败 - 错误码: {:?}",
                GetLastError()
            ),
        }
    }
}

/// 清理系统缓存（去重+优化）
fn clean_system_caches() {
    // 刷新DNS缓存（等待执行完成+错误处理）
    let dns_flush = std::process::Command::new("cmd")
        .args(&["/C", "ipconfig", "/flushdns"])
        .spawn()
        .and_then(|mut child| child.wait().map(|status| status.success()));

    match dns_flush {
        Ok(true) => println!("DNS缓存已刷新"),
        Ok(false) => eprintln!("DNS缓存刷新失败（退出码非0）"),
        Err(e) => eprintln!("DNS缓存刷新失败: {}", e),
    }

    // 预取文件清理
    clean_files_glob("C:\\Windows\\Prefetch\\*.pf");
    println!("预取文件已清理");
}

/// 按文件修改时间清理目录
fn clean_directory_by_age(dir: &Path, days: u64) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }

    let cutoff = SystemTime::now() - Duration::from_secs(days * 86400);

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::metadata(&path)?;

        if metadata.modified()? < cutoff {
            if path.is_dir() {
                fs::remove_dir_all(&path)?;
                println!("删除过期目录: {}", path.display());
            } else {
                fs::remove_file(&path)?;
                println!("删除过期文件: {}", path.display());
            }
        }
    }

    Ok(())
}

/// 清理C盘核心逻辑（合并去重+修复生命周期问题）
fn clean_c_drive() -> Result<()> {
    let user_dir = get_user_dir();

    // 1. 临时文件夹（修复临时值生命周期问题）
    let user_temp_dir = user_dir.join("AppData\\Local\\Temp"); // 用let绑定延长生命周期
    let temp_paths = vec![
        Path::new("C:\\Windows\\Temp"),
        user_temp_dir.as_path(),
    ];
    for path in temp_paths {
        clean_directory_by_age(path, TEMP_FILE_AGE_DAYS)?;
    }

    // 2. 缩略图缓存
    let thumbnail_dir = user_dir.join("AppData\\Local\\Microsoft\\Windows\\Explorer");
    clean_files_glob(&format!("{}\\thumbcache*.db", thumbnail_dir.display()));

    // 3. 浏览器缓存
    let chrome_cache = user_dir.join("AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache");
    let edge_cache = user_dir.join("AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cache");
    let firefox_cache = user_dir.join("AppData\\Roaming\\Mozilla\\Firefox\\Profiles");
    let browser_caches = vec![chrome_cache, edge_cache, firefox_cache];
    for path in browser_caches {
        clean_directory_by_age(&path, CACHE_FILE_AGE_DAYS)?;
    }

    // 4. Windows更新缓存
    let update_cache = Path::new("C:\\Windows\\SoftwareDistribution\\Download");
    if update_cache.exists() {
        for entry in fs::read_dir(update_cache)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                fs::remove_dir_all(&path)?;
            } else {
                fs::remove_file(&path)?;
            }
        }
        println!("Windows更新缓存已清理");
    }

    // 5. 旧日志文件
    let log_paths = vec![
        Path::new("C:\\Windows\\Logs"),
        Path::new("C:\\Windows\\System32\\LogFiles"),
        Path::new("C:\\inetpub\\logs\\LogFiles"),
    ];
    for path in log_paths {
        clean_directory_by_age(path, LOG_FILE_AGE_DAYS)?;
    }

    Ok(())
}

// ===================== 主函数 =====================
fn main() -> Result<()> {
    // 初始化日志
    env_logger::init();

    println!("===== 开始系统清理 =====");

    // 1. 终止非关键进程
    println!("步骤1：终止非关键进程...");
    terminate_non_critical_processes()?;

    // 2. 压缩系统内存
    println!("步骤2：压缩系统内存...");
    compact_system_memory()?;

    // 3. 清理虚拟内存
    println!("步骤3：清理进程虚拟内存...");
    clear_virtual_memory()?;

    // 4. 清理系统缓存
    println!("步骤4：清理系统缓存...");
    clean_system_caches();

    // 5. 清理C盘
    println!("步骤5：清理C盘文件...");
    clean_c_drive()?;

    // 6. 动态提升CPU时钟
    println!("步骤6：调整CPU时钟加速...");
    dynamic_clock_boost(true);

    println!("===== 系统清理完成 =====");
    Ok(())
}