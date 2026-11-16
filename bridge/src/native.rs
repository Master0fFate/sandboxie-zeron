use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::mem::{size_of, zeroed};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INVALID_PARAMETER, ERROR_NO_MORE_FILES, FILETIME, FreeLibrary, GENERIC_READ,
    GetLastError, HANDLE, HMODULE, INVALID_HANDLE_VALUE, STILL_ACTIVE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FILE_READ_ATTRIBUTES,
    FILE_SHARE_READ, FileAttributeTagInfo, FileIdInfo, GetDriveTypeW, GetFileInformationByHandleEx,
    GetFileVersionInfoSizeW, GetFileVersionInfoW, GetFinalPathNameByHandleW, OPEN_EXISTING,
    VS_FIXEDFILEINFO, VerQueryValueW,
};
use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_FREE, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, MEM_RESERVE,
    MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS, PAGE_NOCACHE, PAGE_READONLY, PAGE_READWRITE,
    PAGE_WRITECOMBINE, PAGE_WRITECOPY, VirtualQueryEx,
};
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::SystemInformation::{GetNativeSystemInfo, SYSTEM_INFO};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CreateMutexW, GetCurrentProcessId, GetExitCodeProcess, GetProcessId,
    GetProcessTimes, OpenProcess, PROCESS_INFORMATION, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    ReleaseMutex, STARTUPINFOW, WaitForSingleObject,
};

const HOME: &str = r"C:\Program Files\Sandboxie-Plus";
const INPUT_LIMIT: u64 = 65536;
const NO_INHERITED: u32 = 0x70000000;
const NOT_FOUND: u32 = 0xc000008b;
const WARNING: &str = "Sandboxie monitoring is shared per Windows session. GET2 destructively consumes shared records, can conflict with other viewers and may drop events. exclusive:true acknowledges that no other viewer may start during capture. Sandboxie 1.18.8 has no monitor ownership token: stopping clears the shared buffer, including records for other boxes. Forced termination can leave monitoring enabled. Unattributable or already-exited PIDs are discarded; trace settings are not changed automatically.";
const EVENT_LIMIT: usize = 4096;
const OUTPUT_LIMIT: usize = 2 * 1024 * 1024;
const PROCESS_LIMIT: usize = 512;
const PROCESS_SCAN_LIMIT: usize = 65536;
const REGION_LIMIT: u16 = 256;
const READ_LIMIT: u32 = 4096;
const WRITE_LIMIT: usize = 256;
const WRITE_WARNING: &str = "This powerful local CLI does not request human approval. The plugin service must obtain fresh explicit approval for each exact write. Expected-byte checking and readback are not atomic against target threads or mapping/protection changes. A matching readback is only a point-in-time observation, not a guarantee of persistence or application correctness. No retry or rollback is performed.";
static CANCELLED: AtomicBool = AtomicBool::new(false);
static CAPTURE_ACTIVE: AtomicBool = AtomicBool::new(false);

type GetVersion = unsafe extern "C" fn(*mut u16, *mut u32) -> i32;
type Ioctl = unsafe extern "C" fn(*mut u64) -> i32;
type QueryProcess = unsafe extern "C" fn(HANDLE, *mut u16, *mut u16, *mut u16, *mut u32) -> i32;
type QueryConf = unsafe extern "C" fn(*const u16, *const u16, u32, *mut u16, u32) -> i32;
type IsBoxEnabled = unsafe extern "C" fn(*const u16) -> i32;
type MonitorControl = unsafe extern "C" fn(*mut u32, *mut u32) -> i32;
type RunSandboxed = unsafe extern "C" fn(
    *const u16,
    *const u16,
    *const u16,
    u32,
    *mut STARTUPINFOW,
    *mut PROCESS_INFORMATION,
) -> i32;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Probe {},
    Launch {
        #[serde(rename = "box")]
        box_name: String,
        executable: String,
        args: Vec<String>,
    },
    Trace {
        #[serde(rename = "box")]
        box_name: String,
        seconds: u8,
        #[serde(default)]
        exclusive: bool,
    },
    Settings {
        #[serde(rename = "box")]
        box_name: String,
        values: BTreeMap<String, Option<String>>,
    },
    Processes {
        #[serde(rename = "box")]
        box_name: String,
    },
    Regions {
        #[serde(rename = "box")]
        box_name: String,
        pid: u32,
        created: String,
        #[serde(default = "default_region_start")]
        start: String,
        #[serde(default = "default_region_limit")]
        limit: u16,
    },
    ReadMemory {
        #[serde(rename = "box")]
        box_name: String,
        pid: u32,
        created: String,
        address: String,
        length: u32,
    },
    WriteMemory {
        #[serde(rename = "box")]
        box_name: String,
        pid: u32,
        created: String,
        address: String,
        expected_hex: String,
        data_hex: String,
    },
}

fn default_region_start() -> String {
    hex64(0)
}

fn default_region_limit() -> u16 {
    128
}

struct Library(HMODULE);

impl Drop for Library {
    fn drop(&mut self) {
        unsafe { FreeLibrary(self.0) };
    }
}

impl Library {
    fn symbol(&self, name: &'static [u8]) -> Result<unsafe extern "system" fn() -> isize, String> {
        unsafe { GetProcAddress(self.0, name.as_ptr()) }.ok_or_else(|| {
            format!(
                "missing Sandboxie export {}",
                String::from_utf8_lossy(&name[..name.len() - 1])
            )
        })
    }
}

struct Api {
    _library: Library,
    ioctl: Ioctl,
    query_process: QueryProcess,
    query_conf: QueryConf,
    is_box_enabled: IsBoxEnabled,
    monitor_control: MonitorControl,
    run_sandboxed: RunSandboxed,
    driver_version: String,
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn text(value: &[u16]) -> Result<String, String> {
    let end = value
        .iter()
        .position(|v| *v == 0)
        .ok_or("unterminated Sandboxie string")?;
    String::from_utf16(&value[..end]).map_err(|_| "invalid Sandboxie UTF-16".into())
}

fn nt_status(operation: &str, status: i32) -> Result<(), String> {
    if status == 0 {
        Ok(())
    } else {
        Err(format!("{operation}: NTSTATUS 0x{:08X}", status as u32))
    }
}

fn file_version(path: &Path) -> Result<(), String> {
    let name = wide(path.to_str().ok_or("invalid installation path")?);
    let size = unsafe { GetFileVersionInfoSizeW(name.as_ptr(), null_mut()) };
    if size == 0 || size > 1024 * 1024 {
        return Err(format!("cannot validate version of {}", path.display()));
    }
    let mut buffer = vec![0u8; size as usize];
    if unsafe { GetFileVersionInfoW(name.as_ptr(), 0, size, buffer.as_mut_ptr().cast()) } == 0 {
        return Err(format!("cannot read version of {}", path.display()));
    }
    let mut pointer: *mut c_void = null_mut();
    let mut length = 0;
    if unsafe {
        VerQueryValueW(
            buffer.as_ptr().cast(),
            wide("\\").as_ptr(),
            &mut pointer,
            &mut length,
        )
    } == 0
        || pointer.is_null()
        || length < size_of::<VS_FIXEDFILEINFO>() as u32
    {
        return Err("invalid Sandboxie version resource".into());
    }
    let version = unsafe { pointer.cast::<VS_FIXEDFILEINFO>().read_unaligned() };
    if version.dwSignature != 0xfeef04bd
        || version.dwFileVersionMS != (5 << 16 | 73)
        || version.dwFileVersionLS != 8 << 16
    {
        return Err(format!(
            "unsupported Sandboxie file version in {}; expected 5.73.8.0 (Plus 1.18.8)",
            path.display()
        ));
    }
    Ok(())
}

impl Api {
    fn load() -> Result<Self, String> {
        let path = Path::new(HOME).join("SbieDll.dll");
        file_version(&path)?;
        let name = wide(path.to_str().ok_or("invalid DLL path")?);
        let module = unsafe {
            LoadLibraryExW(
                name.as_ptr(),
                null_mut(),
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() {
            return Err(format!(
                "cannot load trusted SbieDll.dll: {}",
                std::io::Error::last_os_error()
            ));
        }
        let library = Library(module);
        let get_version: GetVersion =
            unsafe { std::mem::transmute(library.symbol(b"SbieApi_GetVersionEx\0")?) };
        let mut version = [0u16; 16];
        let mut abi = 0;
        nt_status("SbieApi_GetVersionEx", unsafe {
            get_version(version.as_mut_ptr(), &mut abi)
        })?;
        let driver_version = text(&version)?;
        if driver_version != "5.73.8" || abi != 0x57230 {
            return Err(format!(
                "unsupported Sandboxie driver {driver_version}, ABI 0x{abi:X}; expected 5.73.8, ABI 0x57230"
            ));
        }
        Ok(Self {
            ioctl: unsafe { std::mem::transmute(library.symbol(b"SbieApi_Ioctl\0")?) },
            query_process: unsafe {
                std::mem::transmute(library.symbol(b"SbieApi_QueryProcess\0")?)
            },
            query_conf: unsafe { std::mem::transmute(library.symbol(b"SbieApi_QueryConf\0")?) },
            is_box_enabled: unsafe {
                std::mem::transmute(library.symbol(b"SbieApi_IsBoxEnabled\0")?)
            },
            monitor_control: unsafe {
                std::mem::transmute(library.symbol(b"SbieApi_MonitorControl\0")?)
            },
            run_sandboxed: unsafe {
                std::mem::transmute(library.symbol(b"SbieDll_RunSandboxed\0")?)
            },
            _library: library,
            driver_version,
        })
    }

    fn query(
        &self,
        section: Option<&str>,
        key: Option<&str>,
        index: u32,
    ) -> Result<Option<String>, String> {
        let section = section.map(wide);
        let key = key.map(wide);
        let mut output = [0u16; 2048];
        let status = unsafe {
            (self.query_conf)(
                section.as_ref().map_or(null(), |s| s.as_ptr()),
                key.as_ref().map_or(null(), |s| s.as_ptr()),
                index | NO_INHERITED,
                output.as_mut_ptr(),
                (output.len() * 2) as u32,
            )
        };
        if status as u32 == NOT_FOUND {
            return Ok(None);
        }
        nt_status("SbieApi_QueryConf", status)?;
        Ok(Some(text(&output)?))
    }

    fn boxes(&self) -> Result<Vec<String>, String> {
        let mut boxes = Vec::new();
        for index in 0..4096 {
            let Some(name) = self.query(None, None, index)? else {
                return Ok(boxes);
            };
            if unsafe { (self.is_box_enabled)(wide(&name).as_ptr()) } == 0 {
                boxes.push(name);
            }
        }
        Err("Sandboxie section limit exceeded".into())
    }

    fn selected_box(&self, name: &str) -> Result<String, String> {
        if name.is_empty()
            || name.len() > 38
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err("invalid box name".into());
        }
        self.boxes()?
            .into_iter()
            .find(|b| b.eq_ignore_ascii_case(name))
            .ok_or_else(|| "box is not in the enabled Sandboxie list for this account".into())
    }

    fn monitoring(&self) -> Result<bool, String> {
        let mut state = 0;
        nt_status("SbieApi_MonitorControl(query)", unsafe {
            (self.monitor_control)(null_mut(), &mut state)
        })?;
        Ok(state != 0)
    }
}

struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

fn hex64(value: u64) -> String {
    format!("0x{value:016x}")
}

fn hexadecimal(value: &str, field: &str) -> Result<u64, String> {
    let digits = value
        .strip_prefix("0x")
        .ok_or_else(|| format!("{field} must be a 0x-prefixed hexadecimal string"))?;
    if digits.is_empty() || digits.len() > 16 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{field} must contain 1 to 16 hexadecimal digits"));
    }
    u64::from_str_radix(digits, 16).map_err(|_| format!("{field} exceeds 64 bits"))
}

fn creation_token(value: &str) -> Result<u64, String> {
    let created = hexadecimal(value, "created")?;
    if created == 0 || value != hex64(created) {
        return Err(
            "created must be a nonzero canonical 0x-prefixed 16-digit lowercase FILETIME".into(),
        );
    }
    Ok(created)
}

fn bytes_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 15) as usize] as char);
    }
    output
}

fn write_bytes(value: &str, field: &str) -> Result<Vec<u8>, String> {
    if value.is_empty()
        || value.len() > WRITE_LIMIT * 2
        || value.len() % 2 != 0
        || !value.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(format!(
            "{field} must be unprefixed even-length hexadecimal encoding of 1 to 256 bytes"
        ));
    }
    Ok(value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| {
                if byte <= b'9' {
                    byte - b'0'
                } else {
                    byte.to_ascii_lowercase() - b'a' + 10
                }
            };
            (digit(pair[0]) << 4) | digit(pair[1])
        })
        .collect())
}

fn win32_error(operation: &str, code: u32) -> String {
    format!(
        "{operation}: Win32 {code}: {}",
        std::io::Error::from_raw_os_error(code as i32)
    )
}

fn session_id(pid: u32) -> Result<u32, String> {
    let mut session = 0;
    if unsafe { ProcessIdToSessionId(pid, &mut session) } == 0 {
        return Err(win32_error("ProcessIdToSessionId", unsafe {
            GetLastError()
        }));
    }
    Ok(session)
}

fn live_creation(handle: HANDLE, pid: u32) -> Result<u64, String> {
    let observed_pid = unsafe { GetProcessId(handle) };
    if observed_pid == 0 {
        return Err(win32_error("GetProcessId", unsafe { GetLastError() }));
    }
    if observed_pid != pid {
        return Err("held process handle does not identify the requested PID".into());
    }
    let mut created = FILETIME::default();
    let mut exited = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    if unsafe { GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) } == 0 {
        return Err(win32_error("GetProcessTimes", unsafe { GetLastError() }));
    }
    let mut exit_code = 0;
    if unsafe { GetExitCodeProcess(handle, &mut exit_code) } == 0 {
        return Err(win32_error("GetExitCodeProcess", unsafe { GetLastError() }));
    }
    let created = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
    if created == 0
        || exited.dwHighDateTime != 0
        || exited.dwLowDateTime != 0
        || exit_code != STILL_ACTIVE as u32
    {
        return Err("held process is no longer live, or its creation time is unavailable".into());
    }
    Ok(created)
}

struct ProcessMembership {
    image: Option<String>,
}

struct TargetProcess {
    handle: Handle,
    pid: u32,
    created: u64,
    session: u32,
}

impl TargetProcess {
    fn open(pid: u32, created: Option<u64>, rights: u32, session: u32) -> Result<Self, String> {
        if pid == 0 {
            return Err("pid must be a nonzero 32-bit integer".into());
        }
        let handle = unsafe { OpenProcess(rights, 0, pid) };
        if handle.is_null() {
            return Err(win32_error("OpenProcess", unsafe { GetLastError() }));
        }
        let handle = Handle(handle);
        let observed = live_creation(handle.0, pid)?;
        if created.is_some_and(|expected| expected != observed) {
            return Err(
                "process creation token does not match the held handle; no PID fallback".into(),
            );
        }
        Ok(Self {
            handle,
            pid,
            created: observed,
            session,
        })
    }

    fn identity(&self) -> Result<(), String> {
        if live_creation(self.handle.0, self.pid)? != self.created {
            return Err("held process creation time changed; no PID fallback".into());
        }
        Ok(())
    }

    fn membership(
        &self,
        api: &Api,
        box_name: &str,
        image: bool,
    ) -> Result<Option<ProcessMembership>, String> {
        self.identity()?;
        nt_status("SbieApi_IsBoxEnabled", unsafe {
            (api.is_box_enabled)(wide(box_name).as_ptr())
        })?;
        let mut name = [0u16; 40];
        let mut image_name = [0u16; 96];
        let mut sandbox_session = u32::MAX;
        let status = unsafe {
            (api.query_process)(
                self.pid as usize as HANDLE,
                name.as_mut_ptr(),
                if image {
                    image_name.as_mut_ptr()
                } else {
                    null_mut()
                },
                null_mut(),
                &mut sandbox_session,
            )
        };
        let windows_session = session_id(self.pid);
        self.identity()?;
        if status as u32 == 0xc000000b {
            return Ok(None);
        }
        nt_status("SbieApi_QueryProcess", status)?;
        if !text(&name)?.eq_ignore_ascii_case(box_name)
            || sandbox_session != self.session
            || windows_session? != self.session
        {
            return Ok(None);
        }
        let image = if image {
            let value = text(&image_name)?;
            if value.is_empty() {
                return Err("Sandboxie process image name is unavailable".into());
            }
            Some(value)
        } else {
            None
        };
        Ok(Some(ProcessMembership { image }))
    }

    fn require_membership(&self, api: &Api, box_name: &str) -> Result<(), String> {
        self.membership(api, box_name, false)?
            .ok_or_else(|| {
                "process is not in the selected sandbox and current Windows session".into()
            })
            .map(|_| ())
    }
}

fn processes(api: &Api, box_name: &str) -> Result<Value, String> {
    let session = session_id(unsafe { GetCurrentProcessId() })?;
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(win32_error("CreateToolhelp32Snapshot", unsafe {
            GetLastError()
        }));
    }
    let snapshot = Handle(snapshot);
    let mut entry = PROCESSENTRY32W::default();
    entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
    let mut available = unsafe { Process32FirstW(snapshot.0, &mut entry) };
    let mut error = if available == 0 {
        let code = unsafe { GetLastError() };
        (code != ERROR_NO_MORE_FILES).then(|| win32_error("Process32FirstW", code))
    } else {
        None
    };
    let mut entries = Vec::new();
    let mut inaccessible = 0u32;
    let mut inspected = 0;
    let mut truncated = false;
    while available != 0 {
        inspected += 1;
        if entry.th32ProcessID != 0 {
            match TargetProcess::open(
                entry.th32ProcessID,
                None,
                PROCESS_QUERY_LIMITED_INFORMATION,
                session,
            )
            .and_then(|process| {
                process
                    .membership(api, box_name, true)
                    .map(|membership| (process, membership))
            }) {
                Ok((process, Some(membership))) => entries.push(json!({
                    "pid":process.pid,"image":membership.image,"created":hex64(process.created)
                })),
                Ok((_, None)) => {}
                Err(_) => inaccessible += 1,
            }
        }
        if entries.len() >= PROCESS_LIMIT || inspected >= PROCESS_SCAN_LIMIT {
            truncated = true;
            break;
        }
        available = unsafe { Process32NextW(snapshot.0, &mut entry) };
        if available == 0 {
            let code = unsafe { GetLastError() };
            if code != ERROR_NO_MORE_FILES {
                error = Some(win32_error("Process32NextW", code));
            }
        }
    }
    truncated |= error.is_some();
    Ok(
        json!({"ok":error.is_none(),"box":box_name,"session":session,"processes":entries,
        "truncated":truncated,"inaccessible":inaccessible,"error":error,
        "warning":"Only live, attributed selected-box processes in this Windows session are identified. inaccessible counts snapshot candidates that could not be safely inspected, not confirmed box members; their PIDs and names are withheld. Enumeration is not a frozen snapshot of process liveness."}),
    )
}

struct AddressSpace {
    maximum: u64,
    page_size: u64,
}

impl AddressSpace {
    fn native() -> Result<Self, String> {
        let mut info = SYSTEM_INFO::default();
        unsafe { GetNativeSystemInfo(&mut info) };
        let maximum = info.lpMaximumApplicationAddress as usize as u64;
        let page_size = u64::from(info.dwPageSize);
        if maximum == 0 || page_size == 0 || !page_size.is_power_of_two() {
            return Err("native application address bounds are unavailable".into());
        }
        Ok(Self { maximum, page_size })
    }

    fn range(&self, address: u64, length: usize) -> Result<u64, String> {
        let end = address
            .checked_add(length as u64)
            .ok_or("memory range overflows 64 bits")?;
        if length == 0 || address > self.maximum || end - 1 > self.maximum {
            return Err("memory range is outside native application address bounds".into());
        }
        Ok(end)
    }

    fn cursor(&self, start: u64) -> Result<(), String> {
        if start > self.maximum || start % self.page_size != 0 {
            return Err(
                "start must be a page-aligned cursor within native application address bounds"
                    .into(),
            );
        }
        Ok(())
    }
}

fn query_region(process: HANDLE, address: u64) -> Result<Option<MEMORY_BASIC_INFORMATION>, String> {
    let mut info = MEMORY_BASIC_INFORMATION::default();
    let length = unsafe {
        VirtualQueryEx(
            process,
            address as usize as *const c_void,
            &mut info,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if length == 0 {
        let code = unsafe { GetLastError() };
        if code == ERROR_INVALID_PARAMETER {
            return Ok(None);
        }
        return Err(win32_error("VirtualQueryEx", code));
    }
    if length != size_of::<MEMORY_BASIC_INFORMATION>() {
        return Err("VirtualQueryEx returned an unexpected structure length".into());
    }
    let base = info.BaseAddress as usize as u64;
    let end = base
        .checked_add(info.RegionSize as u64)
        .ok_or("VirtualQueryEx region overflows 64 bits")?;
    if info.RegionSize == 0 || base > address || end <= address {
        return Err("VirtualQueryEx returned a non-covering or non-progressing region".into());
    }
    Ok(Some(info))
}

fn readable_region(info: &MEMORY_BASIC_INFORMATION) -> bool {
    info.State == MEM_COMMIT
        && info.Protect & !(0xff | PAGE_NOCACHE | PAGE_WRITECOMBINE) == 0
        && matches!(
            info.Protect & 0xff,
            PAGE_READONLY
                | PAGE_READWRITE
                | PAGE_WRITECOPY
                | PAGE_EXECUTE_READ
                | PAGE_EXECUTE_READWRITE
                | PAGE_EXECUTE_WRITECOPY
        )
}

fn write_eligible(info: &MEMORY_BASIC_INFORMATION) -> bool {
    info.State == MEM_COMMIT && info.Type == MEM_PRIVATE && info.Protect == PAGE_READWRITE
}

fn region_value(info: &MEMORY_BASIC_INFORMATION) -> Value {
    let state_name = match info.State {
        MEM_COMMIT => Some("MEM_COMMIT"),
        MEM_RESERVE => Some("MEM_RESERVE"),
        MEM_FREE => Some("MEM_FREE"),
        _ => None,
    };
    let type_name = if info.State == MEM_FREE {
        None
    } else {
        match info.Type {
            MEM_PRIVATE => Some("MEM_PRIVATE"),
            MEM_MAPPED => Some("MEM_MAPPED"),
            MEM_IMAGE => Some("MEM_IMAGE"),
            _ => None,
        }
    };
    let protect_name = if info.State != MEM_COMMIT {
        None
    } else {
        match info.Protect & 0xff {
            PAGE_NOACCESS => Some("PAGE_NOACCESS"),
            PAGE_READONLY => Some("PAGE_READONLY"),
            PAGE_READWRITE => Some("PAGE_READWRITE"),
            PAGE_WRITECOPY => Some("PAGE_WRITECOPY"),
            PAGE_EXECUTE => Some("PAGE_EXECUTE"),
            PAGE_EXECUTE_READ => Some("PAGE_EXECUTE_READ"),
            PAGE_EXECUTE_READWRITE => Some("PAGE_EXECUTE_READWRITE"),
            PAGE_EXECUTE_WRITECOPY => Some("PAGE_EXECUTE_WRITECOPY"),
            _ => None,
        }
    };
    json!({"base":hex64(info.BaseAddress as usize as u64),"size":hex64(info.RegionSize as u64),
        "allocation_base":hex64(info.AllocationBase as usize as u64),"state":info.State,
        "state_name":state_name,"protect":info.Protect,"protect_name":protect_name,
        "allocation_protect":info.AllocationProtect,"type":info.Type,"type_name":type_name,
        "readable":readable_region(info),"guard":info.State == MEM_COMMIT && info.Protect & PAGE_GUARD != 0,
        "executable":info.State == MEM_COMMIT && info.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) != 0,
        "write_eligible":write_eligible(info)})
}

fn regions(
    api: &Api,
    box_name: &str,
    pid: u32,
    created: u64,
    start: u64,
    limit: u16,
) -> Result<Value, String> {
    let space = AddressSpace::native()?;
    space.cursor(start)?;
    if !(1..=REGION_LIMIT).contains(&limit) {
        return Err("limit must be an integer from 1 to 256".into());
    }
    let process = TargetProcess::open(
        pid,
        Some(created),
        PROCESS_QUERY_INFORMATION,
        session_id(unsafe { GetCurrentProcessId() })?,
    )?;
    process.require_membership(api, box_name)?;
    let mut entries = Vec::new();
    let mut cursor = start;
    let mut complete = false;
    let result = (|| {
        while entries.len() < usize::from(limit) {
            let Some(info) = query_region(process.handle.0, cursor)? else {
                if entries.is_empty() {
                    return Err("VirtualQueryEx: Win32 87 (ERROR_INVALID_PARAMETER); start is not queryable in the held process address space".into());
                }
                complete = true;
                break;
            };
            cursor = (info.BaseAddress as usize as u64)
                .checked_add(info.RegionSize as u64)
                .ok_or("region cursor overflows 64 bits")?;
            entries.push(region_value(&info));
            if cursor > space.maximum {
                complete = true;
                break;
            }
        }
        if !complete
            && entries.len() == usize::from(limit)
            && query_region(process.handle.0, cursor)?.is_none()
        {
            complete = true;
        }
        Ok::<(), String>(())
    })();
    process.require_membership(api, box_name)?;
    let error = result.err();
    Ok(
        json!({"ok":error.is_none(),"box":box_name,"pid":pid,"created":hex64(created),
        "start":hex64(start),"limit":limit,"regions":entries,"complete":complete,
        "truncated":!complete,"next":if complete { None } else { Some(hex64(cursor)) },"error":error}),
    )
}

fn checked_memory_region(
    process: HANDLE,
    address: u64,
    end: u64,
    writing: bool,
) -> Result<(), String> {
    let info = query_region(process, address)?
        .ok_or("VirtualQueryEx: Win32 87 (ERROR_INVALID_PARAMETER); memory address is not queryable in the held process")?;
    let region_end = (info.BaseAddress as usize as u64)
        .checked_add(info.RegionSize as u64)
        .ok_or("memory region overflows 64 bits")?;
    if end > region_end {
        return Err("the entire memory range must fit within one VirtualQueryEx region".into());
    }
    if writing && !write_eligible(&info) {
        return Err("write requires one committed, private, non-guard, non-executable region with Protect exactly PAGE_READWRITE".into());
    }
    if !writing && !readable_region(&info) {
        return Err("read requires one committed readable region without guard or unknown protection modifiers".into());
    }
    Ok(())
}

struct MemoryRead {
    win32_success: bool,
    win32_error: Option<u32>,
    reported_count: usize,
    data: Vec<u8>,
    requested: usize,
    error: Option<String>,
}

impl MemoryRead {
    fn complete(&self) -> bool {
        self.win32_success && self.reported_count == self.requested && self.error.is_none()
    }

    fn value(&self, disclose: bool) -> Value {
        json!({"win32_success":self.win32_success,"win32_error":self.win32_error,
            "reported_count":hex64(self.reported_count as u64),"count":self.data.len() as u32,
            "complete":self.complete(),"partial":!self.data.is_empty() && self.data.len() < self.requested,
            "data_hex":if disclose { Some(bytes_hex(&self.data)) } else { None },"error":self.error})
    }
}

fn read_bytes(process: HANDLE, address: u64, length: usize) -> MemoryRead {
    let mut data = vec![0u8; length];
    let mut count = 0;
    let success = unsafe {
        ReadProcessMemory(
            process,
            address as usize as *const c_void,
            data.as_mut_ptr().cast(),
            length,
            &mut count,
        )
    };
    let code = if success == 0 {
        Some(unsafe { GetLastError() })
    } else {
        None
    };
    let error = if count > length {
        data.clear();
        Some(format!(
            "ReadProcessMemory returned an invalid byte count {}; bytes withheld",
            hex64(count as u64)
        ))
    } else {
        data.truncate(count);
        if let Some(code) = code {
            Some(win32_error("ReadProcessMemory", code))
        } else if count != length {
            Some(format!(
                "ReadProcessMemory returned {count} of {length} requested bytes"
            ))
        } else {
            None
        }
    };
    MemoryRead {
        win32_success: success != 0,
        win32_error: code,
        reported_count: count,
        data,
        requested: length,
        error,
    }
}

fn read_memory(
    api: &Api,
    box_name: &str,
    pid: u32,
    created: u64,
    address: u64,
    length: u32,
) -> Result<Value, String> {
    if !(1..=READ_LIMIT).contains(&length) {
        return Err("length must be an integer from 1 to 4096".into());
    }
    let end = AddressSpace::native()?.range(address, length as usize)?;
    let process = TargetProcess::open(
        pid,
        Some(created),
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        session_id(unsafe { GetCurrentProcessId() })?,
    )?;
    process.require_membership(api, box_name)?;
    let access = checked_memory_region(process.handle.0, address, end, false)
        .map(|()| read_bytes(process.handle.0, address, length as usize));
    process.require_membership(api, box_name)?;
    let read = access?;
    let mut response = read.value(true);
    let object = response.as_object_mut().unwrap();
    object.insert("ok".into(), json!(read.complete()));
    object.insert("box".into(), json!(box_name));
    object.insert("pid".into(), json!(pid));
    object.insert("created".into(), json!(hex64(created)));
    object.insert("address".into(), json!(hex64(address)));
    object.insert("length".into(), json!(length));
    Ok(response)
}

fn write_memory(
    api: &Api,
    box_name: &str,
    pid: u32,
    created: u64,
    address: u64,
    expected: &[u8],
    data: &[u8],
) -> Value {
    let mut attempted = false;
    let mut expected_matched = None;
    let mut win32_success = None;
    let mut win32_code = None;
    let mut written = None;
    let mut written_reported = None;
    let mut readback = None;
    let mut identity_error = None;
    let mut verified = false;
    let result = (|| {
        if expected.is_empty() || expected.len() != data.len() || data.len() > WRITE_LIMIT {
            return Err(
                "expected_hex and data_hex must encode the same length from 1 to 256 bytes".into(),
            );
        }
        let end = AddressSpace::native()?.range(address, data.len())?;
        let process = TargetProcess::open(
            pid,
            Some(created),
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            session_id(unsafe { GetCurrentProcessId() })?,
        )?;
        process.require_membership(api, box_name)?;
        let validation = (|| {
            checked_memory_region(process.handle.0, address, end, true)?;
            process.require_membership(api, box_name)?;
            checked_memory_region(process.handle.0, address, end, true)
        })();
        if let Err(error) = validation {
            process.require_membership(api, box_name)?;
            return Err(error);
        }
        let before = read_bytes(process.handle.0, address, data.len());
        if !before.complete() {
            process.require_membership(api, box_name)?;
            return Err(format!(
                "expected-byte read failed; no write attempted: {}",
                before.error.as_deref().unwrap_or("incomplete read")
            ));
        }
        expected_matched = Some(before.data == expected);
        if expected_matched != Some(true) {
            process.require_membership(api, box_name)?;
            return Err("expected bytes do not match; no write attempted".into());
        }
        let mut count = 0;
        attempted = true;
        let success = unsafe {
            WriteProcessMemory(
                process.handle.0,
                address as usize as *const c_void,
                data.as_ptr().cast(),
                data.len(),
                &mut count,
            )
        };
        let code = if success == 0 {
            Some(unsafe { GetLastError() })
        } else {
            None
        };
        let observed = read_bytes(process.handle.0, address, data.len());
        identity_error = process.require_membership(api, box_name).err();
        win32_success = Some(success != 0);
        win32_code = code;
        written = (count <= data.len()).then_some(count as u32);
        written_reported = Some(hex64(count as u64));
        let matches = observed.complete().then(|| observed.data == data);
        let mut observed_value = observed.value(identity_error.is_none());
        observed_value.as_object_mut().unwrap().insert(
            "matches".into(),
            json!(if identity_error.is_none() {
                matches
            } else {
                None
            }),
        );
        readback = Some(observed_value);
        verified = success != 0
            && count == data.len()
            && matches == Some(true)
            && identity_error.is_none();
        let mut errors = Vec::new();
        if let Some(code) = code {
            errors.push(win32_error("WriteProcessMemory", code));
        }
        if count != data.len() {
            errors.push(format!(
                "WriteProcessMemory reported {} of {} requested bytes",
                hex64(count as u64),
                data.len()
            ));
        }
        if let Some(error) = observed.error {
            errors.push(format!("readback failed: {error}"));
        } else if matches != Some(true) {
            errors.push(
                "readback differs from data_hex; target threads may also have changed bytes".into(),
            );
        }
        if let Some(error) = &identity_error {
            errors.push(format!(
                "post-access identity/membership check failed: {error}; readback bytes withheld"
            ));
        }
        if !errors.is_empty() {
            return Err(errors.join("; "));
        }
        Ok(())
    })();
    json!({"ok":verified && result.is_ok(),"box":box_name,"pid":pid,"created":hex64(created),
        "address":hex64(address),"length":data.len() as u32,"attempted":attempted,
        "expected_matched":expected_matched,"win32_success":win32_success,"win32_error":win32_code,
        "written":written,"written_reported":written_reported,"readback":readback,
        "verified":verified,"uncertain":attempted && !verified,"identity_error":identity_error,
        "error":result.err(),"warning":WRITE_WARNING})
}

struct CaptureLock(Handle);

unsafe extern "system" fn console_control(event: u32) -> i32 {
    if !matches!(event, 0 | 1 | 2 | 5 | 6) {
        return 0;
    }
    CANCELLED.store(true, Ordering::SeqCst);
    if event >= 2 {
        for _ in 0..100 {
            if !CAPTURE_ACTIVE.load(Ordering::SeqCst) {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
    1
}

impl CaptureLock {
    fn acquire() -> Result<Self, String> {
        let handle = unsafe {
            CreateMutexW(
                null(),
                0,
                wide(r"Local\ZeronSandboxieBridgeMonitorV1").as_ptr(),
            )
        };
        if handle.is_null() {
            return Err(format!(
                "cannot create monitor lock: {}",
                std::io::Error::last_os_error()
            ));
        }
        let handle = Handle(handle);
        if unsafe { WaitForSingleObject(handle.0, 0) } != WAIT_OBJECT_0 {
            return Err("another bridge owns the monitor lock, or the previous owner exited unexpectedly; no monitor state changed".into());
        }
        CANCELLED.store(false, Ordering::SeqCst);
        if unsafe { SetConsoleCtrlHandler(Some(console_control), 1) } == 0 {
            unsafe { ReleaseMutex(handle.0) };
            return Err(
                "cannot install monitor cancellation handler; no monitor state changed".into(),
            );
        }
        Ok(Self(handle))
    }
}

impl Drop for CaptureLock {
    fn drop(&mut self) {
        unsafe {
            SetConsoleCtrlHandler(Some(console_control), 0);
            ReleaseMutex(self.0.0);
        }
    }
}

struct MonitorLease<'a> {
    api: &'a Api,
    armed: bool,
}

impl MonitorLease<'_> {
    fn finish(&mut self) -> Result<(), String> {
        self.armed = false;
        let mut disabled = 0;
        let result = nt_status("SbieApi_MonitorControl(disable)", unsafe {
            (self.api.monitor_control)(&mut disabled, null_mut())
        })
        .and_then(|()| {
            if self.api.monitoring()? {
                Err("monitor remains enabled after cleanup; no retry".into())
            } else {
                Ok(())
            }
        });
        CAPTURE_ACTIVE.store(false, Ordering::SeqCst);
        result
    }
}

impl Drop for MonitorLease<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.finish();
        }
    }
}

#[derive(Serialize)]
struct Event {
    time: u64,
    pid: u32,
    tid: u32,
    #[serde(rename = "type")]
    kind: u32,
    data: Vec<String>,
    filetime: String,
    record_hex: String,
    data_utf16_valid: bool,
    decoded_type: DecodedType,
    tags: Vec<EventTag>,
}

#[derive(Serialize)]
struct DecodedType {
    type_id: u32,
    type_name: Option<&'static str>,
    disposition: u32,
    result: u32,
    flags: Vec<&'static str>,
    unknown_flags: u32,
}

#[derive(Serialize)]
struct EventTag {
    id: u32,
    name: Option<&'static str>,
    length: u32,
    data_hex: String,
}

fn decode_type(kind: u32) -> DecodedType {
    let type_id = kind & 0xff;
    let type_name = match type_id {
        0x01 => Some("MONITOR_SYSCALL"),
        0x02 => Some("MONITOR_PIPE"),
        0x03 => Some("MONITOR_IPC"),
        0x04 => Some("MONITOR_WINCLASS"),
        0x05 => Some("MONITOR_DRIVE"),
        0x06 => Some("MONITOR_COMCLASS"),
        0x07 => Some("MONITOR_RTCLASS"),
        0x08 => Some("MONITOR_IGNORE"),
        0x09 => Some("MONITOR_IMAGE"),
        0x0a => Some("MONITOR_FILE"),
        0x0b => Some("MONITOR_KEY"),
        0x0c => Some("MONITOR_OTHER"),
        0x0d => Some("MONITOR_NETFW"),
        0x0e => Some("MONITOR_SCM"),
        0x0f => Some("MONITOR_APICALL"),
        0x10 => Some("MONITOR_RPC"),
        0x11 => Some("MONITOR_DNS"),
        0x12 => Some("MONITOR_HOOK"),
        _ => None,
    };
    let known = [
        (0x00010000, "MONITOR_OPEN"),
        (0x00020000, "MONITOR_DENY"),
        (0x00100000, "MONITOR_ALLOWED"),
        (0x00200000, "MONITOR_DENIDED"),
        (0x00400000, "MONITOR_SUCCESS"),
        (0x00800000, "MONITOR_FAILURE"),
        (0x40000000, "MONITOR_TRACE"),
        (0x80000000, "MONITOR_USER"),
    ];
    let mut mask = 0xff;
    let mut flags = Vec::new();
    for (bit, name) in known {
        mask |= bit;
        if kind & bit != 0 {
            flags.push(name);
        }
    }
    DecodedType {
        type_id,
        type_name,
        disposition: kind & 0x000f0000,
        result: kind & 0x00f00000,
        flags,
        unknown_flags: kind & !mask,
    }
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn attributed(api: &Api, pid: u32, timestamp: u64, box_name: &str, session: u32) -> bool {
    let Ok(process) = TargetProcess::open(pid, None, PROCESS_QUERY_LIMITED_INFORMATION, session)
    else {
        return false;
    };
    process.created <= timestamp && process.require_membership(api, box_name).is_ok()
}

fn parse_event(
    api: &Api,
    record: &[u8],
    box_name: &str,
    session: u32,
) -> Result<Option<Event>, String> {
    if record.len() < 20 {
        return Err("invalid GET2 record length".into());
    }
    let timestamp = u64::from_le_bytes(record[..8].try_into().unwrap());
    let pid = u32_at(record, 12);
    if !attributed(api, pid, timestamp, box_name, session) {
        return Ok(None);
    }
    let mut position = 20;
    let mut data = Vec::new();
    let mut data_utf16_valid = true;
    let mut tagged = false;
    while position < record.len() {
        if record.len() - position < 2 {
            return Err("incomplete GET2 UTF-16 code unit".into());
        }
        let character = u16::from_le_bytes(record[position..position + 2].try_into().unwrap());
        position += 2;
        if character == 0xffff {
            tagged = true;
            break;
        }
        let mut string = Vec::new();
        let mut character = character;
        while character != 0 {
            string.push(character);
            if record.len() - position < 2 {
                return Err("unterminated GET2 string".into());
            }
            character = u16::from_le_bytes(record[position..position + 2].try_into().unwrap());
            position += 2;
        }
        data.push(match String::from_utf16(&string) {
            Ok(value) => value,
            Err(_) => {
                data_utf16_valid = false;
                String::from_utf16_lossy(&string)
            }
        });
        if data.len() > 128 {
            return Err("GET2 string count exceeds limit".into());
        }
    }
    if tagged && position == record.len() {
        return Err("GET2 sentinel must precede at least one tag".into());
    }
    let mut tags = Vec::new();
    while position < record.len() {
        if record.len() - position < 8 {
            return Err("invalid GET2 tag header".into());
        }
        let id = u32_at(record, position);
        let length = u32_at(record, position + 4);
        position += 8;
        if length as usize > record.len() - position {
            return Err("invalid GET2 tag length".into());
        }
        tags.push(EventTag {
            id,
            name: (id == u32::from_be_bytes(*b"STCK")).then_some("STCK"),
            length,
            data_hex: bytes_hex(&record[position..position + length as usize]),
        });
        position += length as usize;
    }
    let milliseconds = timestamp
        .checked_sub(116444736000000000)
        .ok_or("invalid GET2 timestamp")?
        / 10000;
    let kind = u32_at(record, 8);
    Ok(Some(Event {
        time: milliseconds,
        pid,
        tid: u32_at(record, 16),
        kind,
        data,
        filetime: hex64(timestamp),
        record_hex: bytes_hex(record),
        data_utf16_valid,
        decoded_type: decode_type(kind),
        tags,
    }))
}

fn collect(
    api: &Api,
    box_name: &str,
    seconds: u8,
    events: &mut Vec<Event>,
    truncated: &mut bool,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(u64::from(seconds));
    let mut buffer = vec![0u8; 1024 * 1024];
    let session = session_id(unsafe { GetCurrentProcessId() })?;
    let mut total_bytes = 0;
    let mut batches = 0;
    let mut records = 0;
    while Instant::now() < deadline && !CANCELLED.load(Ordering::SeqCst) {
        if *truncated {
            thread::sleep(Duration::from_millis(20));
            continue;
        }
        let mut length = buffer.len() as u32;
        let mut arguments = [0u64; 8];
        arguments[0] = 0x12340048;
        arguments[1] = buffer.as_mut_ptr() as u64;
        arguments[2] = &mut length as *mut u32 as u64;
        let status = unsafe { (api.ioctl)(arguments.as_mut_ptr()) };
        if status as u32 == 0x8000001a {
            thread::sleep(Duration::from_millis(20));
            continue;
        }
        if status != 0 && status != 0x105 {
            nt_status("API_MONITOR_GET2", status)?;
        }
        if length < 4 || length as usize > buffer.len() {
            return Err("invalid GET2 buffer length".into());
        }
        batches += 1;
        let bytes = &buffer[..length as usize];
        let mut position = 0;
        loop {
            if position + 4 > bytes.len() {
                return Err("missing GET2 end marker".into());
            }
            let size = u32_at(bytes, position) as usize;
            position += 4;
            if size == 0 {
                if position != bytes.len() {
                    return Err("unexpected bytes after GET2 end marker".into());
                }
                break;
            }
            if size > bytes.len() - position {
                return Err("GET2 record extends beyond buffer".into());
            }
            if Instant::now() >= deadline || CANCELLED.load(Ordering::SeqCst) {
                *truncated = true;
                break;
            }
            records += 1;
            if let Some(event) =
                parse_event(api, &bytes[position..position + size], box_name, session)?
            {
                let encoded = serde_json::to_vec(&event).map_err(|e| e.to_string())?.len() + 1;
                if events.len() >= EVENT_LIMIT || total_bytes + encoded > OUTPUT_LIMIT - 4096 {
                    *truncated = true;
                    break;
                }
                total_bytes += encoded;
                events.push(event);
            }
            position += size;
            if records >= 65536 {
                *truncated = true;
                break;
            }
        }
        if batches >= 64 {
            *truncated = true;
        }
        if status != 0x105 {
            thread::sleep(Duration::from_millis(20));
        }
    }
    if CANCELLED.load(Ordering::SeqCst) {
        return Err("capture cancelled; returned events are partial".into());
    }
    Ok(())
}

fn trace(api: &Api, box_name: &str, seconds: u8, exclusive: bool) -> Value {
    let mut events = Vec::new();
    let mut truncated = false;
    let mut cleanup_error = None;
    let mut capture_started = false;
    let result = (|| {
        let _lock = CaptureLock::acquire()?;
        if api.monitoring()? {
            return Err(
                "monitor_busy: monitoring is already enabled; no records or state changed".into(),
            );
        }
        if !exclusive {
            return Err("exclusive_required: explicitly acknowledge sole-monitor access with exclusive:true; no state changed".into());
        }
        let mut enabled = 1;
        let mut previous = 0;
        nt_status("SbieApi_MonitorControl(enable)", unsafe {
            (api.monitor_control)(&mut enabled, &mut previous)
        })?;
        if previous != 0 {
            return Err("monitor_busy: another monitor started before acquisition; it was not consumed or disabled".into());
        }
        CAPTURE_ACTIVE.store(true, Ordering::SeqCst);
        let mut lease = MonitorLease { api, armed: true };
        let capture = match api.monitoring() {
            Ok(true) => {
                capture_started = true;
                collect(api, box_name, seconds, &mut events, &mut truncated)
            },
            Ok(false) => Err("monitor did not enable; start Sandboxie Manager in this Windows session and ensure monitoring is off; capture was not retried".into()),
            Err(error) => Err(error),
        };
        if let Err(error) = lease.finish() {
            cleanup_error = Some(error);
        }
        capture
    })();
    let error = result.err();
    if capture_started && (error.is_some() || cleanup_error.is_some()) {
        truncated = true;
    }
    json!({"ok":error.is_none() && cleanup_error.is_none(),"box":box_name,"events":events,
        "truncated":truncated,"warning":WARNING,"error":error,"cleanup_error":cleanup_error})
}

fn quote_argument(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    let mut slashes = 0;
    for character in value.chars() {
        if character == '\\' {
            slashes += 1;
            continue;
        }
        let count = if character == '"' {
            slashes * 2 + 1
        } else {
            slashes
        };
        output.extend(std::iter::repeat_n('\\', count));
        output.push(character);
        slashes = 0;
    }
    output.extend(std::iter::repeat_n('\\', slashes * 2));
    output.push('"');
    output
}

fn local_path(value: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    if bytes.len() < 4
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || bytes[2] != b'\\'
        || value[2..].contains(':')
        || value.chars().any(|c| c.is_control() || c == '"')
    {
        return Err("executable must be an absolute local drive path without device syntax or alternate streams".into());
    }
    let drive = wide(&value[..3]);
    if !matches!(unsafe { GetDriveTypeW(drive.as_ptr()) }, 2 | 3 | 5 | 6) {
        return Err("executable must be on a local drive, not a network mapping".into());
    }
    if !Path::new(value)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
    {
        return Err("executable must have a .exe extension".into());
    }
    Ok(())
}

fn ordinary_path(value: &str) -> Result<(), String> {
    if value.encode_utf16().count() >= 260 {
        return Err("executable path exceeds the legacy Win32 MAX_PATH limit".into());
    }
    for component in value[3..].split('\\') {
        if component.is_empty()
            || component.ends_with('.')
            || component.ends_with(' ')
            || component
                .chars()
                .any(|c| matches!(c, '<' | '>' | '|' | '?' | '*' | '/'))
        {
            return Err("executable path has ambiguous Win32 components".into());
        }
        let stem = component
            .split('.')
            .next()
            .unwrap_or_default()
            .trim_end_matches(' ')
            .to_ascii_uppercase();
        if matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        ) || ["COM", "LPT"].iter().any(|prefix| {
            stem.strip_prefix(*prefix).is_some_and(|number| {
                matches!(
                    number,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
        }) {
            return Err("executable path contains a reserved Win32 device name".into());
        }
    }
    Ok(())
}

fn file_identity(handle: HANDLE) -> Result<(u64, [u8; 16]), String> {
    let mut info = FILE_ID_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&mut info as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(format!(
            "cannot identify executable: {}",
            std::io::Error::last_os_error()
        ));
    }
    if info.FileId.Identifier == [0; 16] {
        return Err("executable file identity is unavailable".into());
    }
    Ok((info.VolumeSerialNumber, info.FileId.Identifier))
}

fn pinned_entry(path: &Path, directory: bool) -> Result<Handle, String> {
    let name = wide(path.to_str().ok_or("invalid executable path")?);
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(format!(
            "cannot pin executable path: {}",
            std::io::Error::last_os_error()
        ));
    }
    let handle = Handle(handle);
    let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            handle.0,
            FileAttributeTagInfo,
            (&mut info as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    } == 0
    {
        return Err(format!(
            "cannot inspect executable path: {}",
            std::io::Error::last_os_error()
        ));
    }
    if info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err("resolved executable path contains a reparse point".into());
    }
    if (info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
        return Err("resolved executable path has an unexpected entry type".into());
    }
    Ok(handle)
}

struct Executable {
    path: String,
    _file: File,
    _confirmed: Handle,
    _entries: Vec<Handle>,
}

fn executable(value: &str) -> Result<Executable, String> {
    local_path(value)?;
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(value)
        .map_err(|e| format!("cannot open executable: {e}"))?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("executable is not a regular file".into());
    }
    let mut path = vec![0u16; 32768];
    let length = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            path.as_mut_ptr(),
            path.len() as u32,
            0,
        )
    };
    if length == 0 || length as usize >= path.len() {
        return Err("cannot resolve executable path".into());
    }
    let final_path =
        String::from_utf16(&path[..length as usize]).map_err(|_| "invalid executable path")?;
    let final_path = final_path
        .strip_prefix(r"\\?\")
        .ok_or("unexpected executable path format")?
        .to_owned();
    local_path(&final_path)?;
    ordinary_path(&final_path)?;
    let mut entries = Vec::new();
    let parent = Path::new(&final_path)
        .parent()
        .ok_or("invalid executable directory")?;
    for directory in parent.ancestors().collect::<Vec<_>>().into_iter().rev() {
        entries.push(pinned_entry(directory, true)?);
    }
    entries.push(pinned_entry(Path::new(&final_path), false)?);
    let confirmed = unsafe {
        CreateFileW(
            wide(&final_path).as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            null(),
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    };
    if confirmed == INVALID_HANDLE_VALUE {
        return Err(format!(
            "cannot reopen executable through Win32: {}",
            std::io::Error::last_os_error()
        ));
    }
    let confirmed = Handle(confirmed);
    if file_identity(file.as_raw_handle())? != file_identity(confirmed.0)? {
        return Err("ordinary Win32 path does not identify the opened executable".into());
    }
    Ok(Executable {
        path: final_path,
        _file: file,
        _confirmed: confirmed,
        _entries: entries,
    })
}

fn launch(api: &Api, box_name: &str, path: &str, args: &[String]) -> Result<Value, String> {
    if args.len() > 128 || args.iter().any(|a| a.contains('\0')) {
        return Err("launch accepts at most 128 arguments without NUL characters".into());
    }
    let executable = executable(path)?;
    let path = &executable.path;
    let mut command_line = quote_argument(path);
    for arg in args {
        command_line.push(' ');
        command_line.push_str(&quote_argument(arg));
    }
    if command_line.encode_utf16().count() > 8190 {
        return Err("launch command exceeds the supported 8190 UTF-16 code units".into());
    }
    let parent = Path::new(&path)
        .parent()
        .and_then(Path::to_str)
        .ok_or("invalid executable directory")?;
    let mut startup: STARTUPINFOW = unsafe { zeroed() };
    startup.cb = size_of::<STARTUPINFOW>() as u32;
    let mut process: PROCESS_INFORMATION = unsafe { zeroed() };
    let success = unsafe {
        (api.run_sandboxed)(
            wide(box_name).as_ptr(),
            wide(&command_line).as_ptr(),
            wide(parent).as_ptr(),
            0,
            &mut startup,
            &mut process,
        )
    };
    let error = std::io::Error::last_os_error();
    unsafe {
        if !process.hThread.is_null() {
            CloseHandle(process.hThread);
        }
        if !process.hProcess.is_null() {
            CloseHandle(process.hProcess);
        }
    }
    if success == 0 {
        return Err(format!(
            "SbieDll_RunSandboxed rejected the launch: {error}; launch was not retried"
        ));
    }
    Ok(
        json!({"ok": true, "requested": true, "verified": false, "pid": process.dwProcessId,
        "warning": "Launch requested only. The process may exit immediately or fail during sandbox initialization; no process execution or sandbox membership was verified."}),
    )
}

fn validate_settings(values: &BTreeMap<String, Option<String>>) -> Result<(), String> {
    if values.is_empty() || values.len() > 8 {
        return Err("settings requires 1 to 8 explicitly specified keys".into());
    }
    for (key, value) in values {
        let valid = match key.as_str() {
            "FileTrace" | "KeyTrace" | "PipeTrace" | "IpcTrace" => {
                matches!(value.as_deref(), Some("AD" | "A" | "D") | None)
            }
            "ApiTrace" | "DebugTrace" | "ErrorTrace" | "HookTrace" => {
                matches!(value.as_deref(), Some("y") | None)
            }
            _ => false,
        };
        if !valid {
            return Err(format!(
                "disallowed trace setting or value: {key}; use AD/A/D/null for resource traces, y/null for other traces"
            ));
        }
    }
    Ok(())
}

fn ini_set(box_name: &str, key: &str, value: Option<&str>) -> Result<(), String> {
    let path = PathBuf::from(HOME).join("SbieIni.exe");
    file_version(&path)?;
    let mut command = Command::new(path);
    command.current_dir(HOME).args(["set", box_name, key]);
    if let Some(value) = value {
        command.arg(value);
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| format!("cannot start SbieIni: {e}"))?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return if status.success() {
                    Ok(())
                } else {
                    Err(format!("SbieIni exited {status}"))
                };
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            result => {
                let reason = match result {
                    Err(error) => error.to_string(),
                    _ => "10-second timeout".into(),
                };
                let kill = child.kill();
                let wait = child.wait();
                return Err(format!(
                    "SbieIni {reason}; termination={kill:?}, reap={wait:?}; configuration may have changed; no retry or rollback"
                ));
            }
        }
    }
}

fn readback(api: &Api, box_name: &str, key: &str) -> Result<Vec<String>, String> {
    let mut values = Vec::new();
    for index in 0..64 {
        match api.query(Some(box_name), Some(key), index)? {
            Some(value) => values.push(value),
            None => return Ok(values),
        }
    }
    Err("setting readback exceeds 64 values".into())
}

fn settings(api: &Api, box_name: &str, values: BTreeMap<String, Option<String>>) -> Value {
    let mut results = Vec::new();
    let mut stopped = false;
    for (key, value) in values {
        if stopped {
            results.push(json!({"key":key,"requested":value,"ok":false,"attempted":false,"error":"not attempted after an earlier failure"}));
            continue;
        }
        let mutation = ini_set(box_name, &key, value.as_deref());
        let observed = readback(api, box_name, &key);
        let expected: Vec<String> = value.iter().cloned().collect();
        let failure = match (&mutation, &observed) {
            (Err(error), _) => Some(error.clone()),
            (_, Err(error)) => Some(format!(
                "readback failed: {error}; configuration may have changed"
            )),
            (_, Ok(actual)) if actual != &expected => Some(
                "SbieIni readback mismatch; configuration may have changed; no retry or rollback"
                    .into(),
            ),
            _ => None,
        };
        stopped = failure.is_some();
        results.push(
            json!({"key":key,"requested":value,"ok":!stopped,"attempted":true,
            "readback":observed.ok(),"error":failure}),
        );
    }
    json!({"ok":!stopped,"box":box_name,"results":results,
        "warning":"Only requested per-box keys were written. Changes are sequential, not transactional; failures stop later writes without retry or rollback. Existing sandbox processes may need restarting for trace settings to take effect."})
}

fn dispatch(request: Request) -> Result<Value, String> {
    if let Request::Settings { values, .. } = &request {
        validate_settings(values)?;
    }
    if let Request::Trace { seconds, .. } = &request {
        if !(1..=15).contains(seconds) {
            return Err("seconds must be an integer from 1 to 15".into());
        }
    }
    let api = Api::load()?;
    match request {
        Request::Probe {} => Ok(
            json!({"ok":true,"version":"1.18.8","driver_version":api.driver_version,
            "boxes":api.boxes()?,"capabilities":{"launch":true,"settings":true,"trace":true,"trace_requires_exclusive":true,
                "processes":true,"regions":true,"read_memory":true,"read_memory_max_bytes":READ_LIMIT,
                "write_memory":true,"write_memory_max_bytes":WRITE_LIMIT,"memory_requires_created":true,
                "memory_current_session_only":true,"write_requires_external_approval":true},"warning":WARNING}),
        ),
        Request::Launch {
            box_name,
            executable,
            args,
        } => launch(&api, &api.selected_box(&box_name)?, &executable, &args),
        Request::Settings { box_name, values } => {
            Ok(settings(&api, &api.selected_box(&box_name)?, values))
        }
        Request::Trace {
            box_name,
            seconds,
            exclusive,
        } => {
            let box_name = api.selected_box(&box_name)?;
            Ok(trace(&api, &box_name, seconds, exclusive))
        }
        Request::Processes { box_name } => processes(&api, &api.selected_box(&box_name)?),
        Request::Regions {
            box_name,
            pid,
            created,
            start,
            limit,
        } => {
            let created = creation_token(&created)?;
            let start = hexadecimal(&start, "start")?;
            regions(
                &api,
                &api.selected_box(&box_name)?,
                pid,
                created,
                start,
                limit,
            )
        }
        Request::ReadMemory {
            box_name,
            pid,
            created,
            address,
            length,
        } => {
            let created = creation_token(&created)?;
            let address = hexadecimal(&address, "address")?;
            read_memory(
                &api,
                &api.selected_box(&box_name)?,
                pid,
                created,
                address,
                length,
            )
        }
        Request::WriteMemory {
            box_name,
            pid,
            created,
            address,
            expected_hex,
            data_hex,
        } => {
            let created = creation_token(&created)?;
            let address = hexadecimal(&address, "address")?;
            let expected = write_bytes(&expected_hex, "expected_hex")?;
            let data = write_bytes(&data_hex, "data_hex")?;
            Ok(write_memory(
                &api,
                &api.selected_box(&box_name)?,
                pid,
                created,
                address,
                &expected,
                &data,
            ))
        }
    }
}

pub fn run() -> i32 {
    let result = (|| {
        let mut input = Vec::new();
        std::io::stdin()
            .take(INPUT_LIMIT + 1)
            .read_to_end(&mut input)
            .map_err(|e| format!("stdin: {e}"))?;
        if input.len() as u64 > INPUT_LIMIT {
            return Err("request exceeds 65536 bytes".into());
        }
        let request =
            serde_json::from_slice(&input).map_err(|e| format!("invalid request: {e}"))?;
        dispatch(request)
    })();
    let response = result.unwrap_or_else(|error| json!({"ok":false,"error":error}));
    let success = response.get("ok").and_then(Value::as_bool) == Some(true);
    let mut stdout = std::io::stdout().lock();
    if serde_json::to_writer(&mut stdout, &response).is_err()
        || stdout.write_all(b"\n").is_err()
        || stdout.flush().is_err()
    {
        return 1;
    }
    i32::from(!success)
}
