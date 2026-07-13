#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// ─────────────────────────────────── hwid ────────────────────────────────────

mod hwid {
    use sha2::{Digest, Sha256};

    fn collect_macs() -> Vec<[u8; 6]> {
        let mut macs: Vec<[u8; 6]> = Vec::new();
        #[cfg(target_os = "windows")]
        {
            if let Ok(iter) = mac_address::MacAddressIterator::new() {
                for mac in iter {
                    let bytes = mac.bytes();
                    if bytes != [0u8; 6] { macs.push(bytes); }
                }
            }
        }
        if macs.is_empty() {
            if let Ok(Some(mac)) = mac_address::get_mac_address() {
                let bytes = mac.bytes();
                if bytes != [0u8; 6] { macs.push(bytes); }
            }
        }
        macs.sort_unstable();
        macs.dedup();
        macs
    }

    pub fn generate() -> Option<String> {
        let macs = collect_macs();
        if macs.is_empty() { return None; }
        let mut hasher = Sha256::new();
        for mac in &macs { hasher.update(mac); }
        Some(hex::encode(hasher.finalize()))
    }
}

// ──────────────────────────────── process_mgr ────────────────────────────────

mod process_mgr {
    use std::path::Path;
    use std::process::Command;
    use sysinfo::System;

    const TARGET_PROCESSES: &[&str] = &["client32.exe", "runplugin.exe", "runplugin64.exe"];

    pub fn terminate_old_processes() -> usize {
        let mut sys = System::new_all();
        sys.refresh_all();
        let mut killed = 0usize;
        for (pid, process) in sys.processes() {
            let name = process.name().to_string_lossy().to_lowercase();
            if TARGET_PROCESSES.contains(&name.as_str()) {
                if process.kill() {
                    println!("[process_mgr] Terminated {} (PID {})", process.name().to_string_lossy(), pid);
                    killed += 1;
                }
            }
        }
        killed
    }

    pub fn spawn_all_processes(dir: &Path) {
        for name in TARGET_PROCESSES {
            let path = dir.join(name);
            match Command::new(&path).spawn() {
                Ok(child) => println!("[process_mgr] Launched {} (PID {})", path.display(), child.id()),
                Err(e) => eprintln!("[process_mgr] Failed to launch {}: {e}", path.display()),
            }
        }
    }
}

// ────────────────────────────────── auth ─────────────────────────────────────

mod auth {
    use reqwest::Client;
    use serde::{Deserialize, Serialize};
    use std::time::Duration;

    const BASE_URL: &str = "https://hetcuu.com/antisupport";
    const TIMEOUT_SECS: u64 = 10;

    fn client() -> Result<Client, reqwest::Error> {
        Client::builder().timeout(Duration::from_secs(TIMEOUT_SECS)).build()
    }

    #[derive(Serialize)]
    struct ActivateRequest<'a> { username: &'a str, password: &'a str, hwid: &'a str }

    #[derive(Serialize)]
    struct TokenBody<'a> { token: &'a str }

    #[derive(Debug, Deserialize)]
    pub struct ActivateResponse {
        pub success: bool,
        #[serde(default)] pub message: String,
        #[serde(default)] pub token: String,
        #[serde(default)] pub plan_name: String,
        #[serde(default)] pub expiry_date: String,
        #[serde(default)] pub days_left: i32,
        #[serde(default = "default_ttl")] pub _session_ttl: u64,
        #[serde(default = "default_interval")] pub heartbeat_interval: u64,
    }

    fn default_ttl() -> u64 { 300 }
    fn default_interval() -> u64 { 120 }

    #[derive(Debug, Deserialize)]
    pub struct HeartbeatResponse {
        pub success: bool,
        #[serde(default)] pub message: String,
        #[serde(default)] pub expiry_date: String,
        #[serde(default)] pub days_left: i32,
        #[serde(default = "default_interval")] pub heartbeat_interval: u64,
    }

    fn net_err(e: reqwest::Error) -> String {
        if e.is_timeout() {
            "Hết thời gian kết nối. Kiểm tra mạng và thử lại.".into()
        } else if e.is_connect() {
            "Không thể kết nối đến máy chủ. Kiểm tra kết nối mạng.".into()
        } else {
            "Lỗi mạng. Vui lòng thử lại.".into()
        }
    }

    pub async fn activate(username: &str, password: &str, hwid: &str) -> Result<ActivateResponse, String> {
        let c = client().map_err(|_| "Không khởi tạo được HTTP client.".to_string())?;
        let resp = c
            .post(format!("{BASE_URL}/api/activate"))
            .json(&ActivateRequest { username, password, hwid })
            .send().await.map_err(net_err)?;
        resp.json::<ActivateResponse>().await
            .map_err(|_| "Phản hồi từ máy chủ không hợp lệ.".into())
    }

    pub async fn heartbeat(token: &str) -> Result<HeartbeatResponse, String> {
        let c = client().map_err(|_| "Không khởi tạo được HTTP client.".to_string())?;
        let resp = c
            .post(format!("{BASE_URL}/api/heartbeat"))
            .json(&TokenBody { token })
            .send().await.map_err(net_err)?;
        resp.json::<HeartbeatResponse>().await
            .map_err(|_| "Phản hồi heartbeat không hợp lệ.".into())
    }

    pub async fn deactivate(token: String) {
        if let Ok(c) = client() {
            let _ = c.post(format!("{BASE_URL}/api/deactivate"))
                .json(&TokenBody { token: &token })
                .send().await;
        }
    }
}

// ─────────────────────────────────── app ─────────────────────────────────────

mod app {
    use eframe::egui::{self, Align2, Color32, Key, RichText, Stroke, Vec2};
    use std::time::{Duration, Instant};
    use tokio::sync::oneshot;

    const TRIAL_SESSION_SECS: u64 = 180;
    const TRIAL_WARN_SECS: u64 = 10;
    const HETCUU_DIR: &str = r"C:\Program Files (x86)\NetSupport\NetSupport School";
    const SHOP_URL: &str = "https://hetcuu.com/antisupport";

    // Màu thương hiệu
    const C_ACCENT: Color32 = Color32::from_rgb(99, 102, 241);   // indigo
    const C_SUCCESS: Color32 = Color32::from_rgb(34, 197, 94);   // green
    const C_DANGER: Color32  = Color32::from_rgb(239, 68, 68);   // red
    const C_BUY: Color32     = Color32::from_rgb(234, 88, 12);   // orange
    const C_ON: Color32      = Color32::from_rgb(22, 163, 74);
    const C_OFF: Color32     = Color32::from_rgb(220, 38, 38);
    const C_MUTED: Color32   = Color32::from_rgb(148, 163, 184);
    const C_PANEL: Color32   = Color32::from_rgb(15, 23, 42);    // dark navy
    const C_CARD: Color32    = Color32::from_rgb(30, 41, 59);

    fn open_url(url: &str) {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn();
    }

    #[derive(Clone, Copy, PartialEq)]
    enum State { Login, Authenticating, Session }

    pub struct TdcApp {
        username: String,
        password: String,
        auth_error: Option<String>,
        state: State,
        hwid: String,
        runtime: tokio::runtime::Runtime,

        // activate
        auth_rx: Option<oneshot::Receiver<Result<crate::auth::ActivateResponse, String>>>,

        // licensed session
        token: Option<String>,
        heartbeat_interval: u64,
        plan_name: String,
        expiry_date: String,
        days_left: i32,

        // heartbeat loop
        heartbeat_rx: Option<oneshot::Receiver<Result<crate::auth::HeartbeatResponse, String>>>,
        next_heartbeat_at: Option<Instant>,

        // trial
        is_trial: bool,
        session_start: Instant,
        popup_visible: bool,
        popup_start: Option<Instant>,

        // 60-second login window — hết giờ → spawn processes + close
        login_deadline: Instant,
    }

    impl TdcApp {
        pub fn new(hwid: String, runtime: tokio::runtime::Runtime) -> Self {
            crate::process_mgr::terminate_old_processes();
            Self {
                username: String::new(), password: String::new(),
                auth_error: None, state: State::Login, hwid, runtime,
                auth_rx: None,
                token: None, heartbeat_interval: 120,
                plan_name: String::new(), expiry_date: String::new(), days_left: 0,
                heartbeat_rx: None, next_heartbeat_at: None,
                is_trial: false, session_start: Instant::now(),
                popup_visible: false, popup_start: None,
                login_deadline: Instant::now() + Duration::from_secs(180),
            }
        }

        // ── helpers ───────────────────────────────────────────────────────────

        fn begin_licensed(&mut self) {

            self.is_trial = false;
            self.state = State::Session;
            self.next_heartbeat_at = Some(Instant::now() + Duration::from_secs(self.heartbeat_interval));
            self.launch_target();
        }

        fn begin_trial(&mut self) {

            self.is_trial = true;
            self.state = State::Session;
            self.session_start = Instant::now();
            self.popup_visible = false;
            self.popup_start = None;
            self.launch_target();
        }

        fn renew_trial(&mut self) {
            self.session_start = Instant::now();
            self.popup_visible = false;
            self.popup_start = None;
            self.launch_target();
        }

        fn launch_target(&self) {
            crate::process_mgr::terminate_old_processes();
            crate::process_mgr::spawn_all_processes(std::path::Path::new(HETCUU_DIR));
        }

        // ── activate polling ──────────────────────────────────────────────────

        fn poll_auth(&mut self) {
            use tokio::sync::oneshot::error::TryRecvError;
            let Some(rx) = self.auth_rx.as_mut() else { return };
            match rx.try_recv() {
                Ok(Ok(resp)) => {
                    self.auth_rx = None;
                    if resp.success {
                        self.token = Some(resp.token);
                        self.heartbeat_interval = resp.heartbeat_interval;
                        self.plan_name = resp.plan_name;
                        self.expiry_date = resp.expiry_date;
                        self.days_left = resp.days_left;
                        self.begin_licensed();
                    } else {
                        self.state = State::Login;
                        self.auth_error = Some(
                            if resp.message.is_empty() { "Kích hoạt thất bại.".into() }
                            else { resp.message }
                        );
                    }
                }
                Ok(Err(e)) => {
                    self.auth_rx = None;
                    self.state = State::Login;
                    self.auth_error = Some(e);
                }
                Err(TryRecvError::Closed) => {
                    self.auth_rx = None; self.state = State::Login;
                    self.auth_error = Some("Lỗi nội bộ. Vui lòng thử lại.".into());
                }
                Err(TryRecvError::Empty) => {}
            }
        }

        // ── heartbeat ────────────────────────────────────────────────────────

        fn check_heartbeat(&mut self, ctx: &egui::Context) {
            if self.heartbeat_rx.is_some() { return }
            let Some(at) = self.next_heartbeat_at else { return };
            if Instant::now() < at { return }
            self.next_heartbeat_at = None;
            let Some(token) = self.token.clone() else { return };
            let (tx, rx) = oneshot::channel();
            self.heartbeat_rx = Some(rx);
            let ctx2 = ctx.clone();
            self.runtime.spawn(async move {
                let _ = tx.send(crate::auth::heartbeat(&token).await);
                ctx2.request_repaint();
            });
        }

        fn poll_heartbeat(&mut self, ctx: &egui::Context) {
            use tokio::sync::oneshot::error::TryRecvError;
            let Some(rx) = self.heartbeat_rx.as_mut() else { return };
            match rx.try_recv() {
                Ok(Ok(resp)) => {
                    self.heartbeat_rx = None;
                    if resp.success {
                        self.days_left = resp.days_left;
                        self.expiry_date = resp.expiry_date;
                        self.heartbeat_interval = resp.heartbeat_interval;
                        self.next_heartbeat_at = Some(Instant::now() + Duration::from_secs(self.heartbeat_interval));
                    } else {
                        // Server revoked — kick back to login
                        self.token = None;
                        self.next_heartbeat_at = None;
                        self.state = State::Login;
                        self.auth_error = Some(
                            if resp.message.is_empty() { "Phiên đã hết. Vui lòng đăng nhập lại.".into() }
                            else { resp.message }
                        );
                        crate::process_mgr::terminate_old_processes();
                    }
                }
                Ok(Err(_)) => {
                    // Network error — retry silently next interval
                    self.heartbeat_rx = None;
                    self.next_heartbeat_at = Some(Instant::now() + Duration::from_secs(self.heartbeat_interval));
                }
                Err(TryRecvError::Closed) => {
                    self.heartbeat_rx = None;
                    self.next_heartbeat_at = Some(Instant::now() + Duration::from_secs(self.heartbeat_interval));
                }
                Err(TryRecvError::Empty) => {}
            }
            if let Some(at) = self.next_heartbeat_at {
                ctx.request_repaint_after(at.saturating_duration_since(Instant::now()));
            }
        }

        // ── login screen ──────────────────────────────────────────────────────

        fn draw_login(&mut self, ctx: &egui::Context) {
            let is_authing = self.state == State::Authenticating;
            let enter = ctx.input(|i| i.key_pressed(Key::Enter));
            let can_submit = !is_authing && !self.username.is_empty() && !self.password.is_empty();

            // Chỉ hiện/xử lý đếm ngược khi đang ở màn login (không phải đang authing)
            let deadline_secs: Option<u64> = if self.state == State::Login {
                let now = Instant::now();
                Some(if self.login_deadline > now { (self.login_deadline - now).as_secs() } else { 0 })
            } else {
                None
            };

            let mut do_activate = false;
            let mut do_trial = false;
            let mut do_buy = false;


            egui::CentralPanel::default()
                .frame(egui::Frame::none().fill(C_PANEL))
                .show(ctx, |ui| {
                    ui.set_min_size(ui.available_size());
                    ui.vertical_centered(|ui| {
                        ui.add_space(14.0);

                        // ── logo / title ──
                        ui.label(
                            RichText::new("AntiSupport")
                                .size(26.0)
                                .strong()
                                .color(C_ACCENT),
                        );
                        ui.label(
                            RichText::new("hetcuu.com/antisupport")
                                .size(10.0)
                                .color(C_MUTED),
                        );

                        if let Some(secs) = deadline_secs {
                            ui.add_space(2.0);
                            let col = if secs > 10 { C_MUTED } else { C_DANGER };
                            ui.label(
                                RichText::new(format!("Tu dong mo sau {secs}s"))
                                    .size(10.0).color(col),
                            );
                        }

                        ui.add_space(10.0);

                        // ── form card ──
                        egui::Frame::none()
                            .fill(C_CARD)
                            .rounding(8.0)
                            .inner_margin(egui::Margin::symmetric(14.0, 10.0))
                            .show(ui, |ui| {
                                ui.set_width(230.0);
                                egui::Grid::new("login_grid")
                                    .num_columns(2)
                                    .spacing([8.0, 5.0])
                                    .show(ui, |ui| {
                                        ui.label(RichText::new("Tai khoan").color(C_MUTED).size(11.0));
                                        ui.add_enabled(
                                            !is_authing,
                                            egui::TextEdit::singleline(&mut self.username)
                                                .desired_width(160.0)
                                                .hint_text("username"),
                                        );
                                        ui.end_row();

                                        ui.label(RichText::new("Mat khau").color(C_MUTED).size(11.0));
                                        ui.add_enabled(
                                            !is_authing,
                                            egui::TextEdit::singleline(&mut self.password)
                                                .password(true)
                                                .desired_width(160.0)
                                                .hint_text("••••••••"),
                                        );
                                        ui.end_row();
                                    });

                                // ── error — bên trong card, luôn hiển thị ──
                                if let Some(err) = &self.auth_error {
                                    ui.add_space(6.0);
                                    egui::Frame::none()
                                        .fill(Color32::from_rgb(69, 10, 10))
                                        .stroke(Stroke::new(1.0, C_DANGER))
                                        .rounding(5.0)
                                        .inner_margin(egui::Margin::symmetric(8.0, 5.0))
                                        .show(ui, |ui| {
                                            ui.set_width(214.0);
                                            ui.label(
                                                RichText::new(err.as_str())
                                                    .size(10.5)
                                                    .color(Color32::from_rgb(252, 165, 165)),
                                            );
                                        });
                                }

                                ui.add_space(8.0);

                                if is_authing {
                                    ui.horizontal(|ui| {
                                        ui.spinner();
                                        ui.label(RichText::new("Dang xac thuc...").size(11.0).color(C_MUTED));
                                    });
                                    ctx.request_repaint_after(Duration::from_millis(80));
                                } else {
                                    // Primary: Kích hoạt
                                    let btn = egui::Button::new(
                                        RichText::new("  Kich hoat  ").size(13.0).color(Color32::WHITE),
                                    )
                                    .fill(if can_submit { C_ACCENT } else { Color32::from_rgb(55, 65, 81) })
                                    .min_size(Vec2::new(214.0, 28.0));
                                    if ui.add_enabled(can_submit, btn).clicked() || (can_submit && enter) {
                                        do_activate = true;
                                    }

                                    ui.add_space(4.0);

                                    // Secondary row: Mua + Dùng thử
                                    ui.horizontal(|ui| {
                                        let buy_btn = egui::Button::new(
                                            RichText::new("  Mua phan mem  ").size(11.0).color(Color32::WHITE),
                                        )
                                        .fill(C_BUY)
                                        .min_size(Vec2::new(103.0, 24.0));
                                        if ui.add(buy_btn).on_hover_text(SHOP_URL).clicked() {
                                            do_buy = true;
                                        }

                                        let trial_btn = egui::Button::new(
                                            RichText::new("  Dung thu  ").size(11.0).color(C_MUTED),
                                        )
                                        .fill(Color32::from_rgb(30, 41, 59))
                                        .stroke(Stroke::new(1.0, Color32::from_rgb(71, 85, 105)))
                                        .min_size(Vec2::new(103.0, 24.0));
                                        if ui.add(trial_btn).on_hover_text("Phien local 3 phut, khong can tai khoan").clicked() {
                                            do_trial = true;
                                        }
                                    });
                                }
                            });

                        ui.add_space(8.0);

                        // ── HWID footer ──
                        ui.separator();
                        ui.add_space(2.0);
                        ui.label(
                            RichText::new(format!("HWID  {}", &self.hwid[..20]))
                                .size(9.0)
                                .color(Color32::from_rgb(71, 85, 105)),
                        );
                    });
                });


            if do_activate { self.submit_activate(ctx); }
            if do_trial    { self.begin_trial(); }
            if do_buy      { open_url(SHOP_URL); }

            // Hết 1 phút mà chưa login → mở app bình thường rồi đóng cửa sổ
            if self.state == State::Login {
                if Instant::now() >= self.login_deadline {
                    crate::process_mgr::spawn_all_processes(
                        std::path::Path::new(HETCUU_DIR),
                    );
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    return;
                }
                ctx.request_repaint_after(Duration::from_millis(200));
            }
        }

        fn submit_activate(&mut self, ctx: &egui::Context) {
            self.auth_error = None;

            self.state = State::Authenticating;
            let (tx, rx) = oneshot::channel();
            self.auth_rx = Some(rx);
            let (u, p, h) = (self.username.clone(), self.password.clone(), self.hwid.clone());
            let ctx2 = ctx.clone();
            self.runtime.spawn(async move {
                let _ = tx.send(crate::auth::activate(&u, &p, &h).await);
                ctx2.request_repaint();
            });
        }

        // ── session screens ───────────────────────────────────────────────────

        fn draw_session(&mut self, ctx: &egui::Context) {
            if self.is_trial { self.draw_trial(ctx); } else { self.draw_licensed(ctx); }
        }

        fn draw_licensed(&mut self, ctx: &egui::Context) {
            let mut do_on = false;
            let mut do_off = false;

            egui::CentralPanel::default()
                .frame(egui::Frame::none().fill(C_PANEL))
                .show(ctx, |ui| {
                    ui.set_min_size(ui.available_size());
                    ui.vertical_centered(|ui| {
                        ui.add_space(14.0);

                        // ── header ──
                        ui.label(
                            RichText::new("AntiSupport")
                                .size(22.0)
                                .strong()
                                .color(C_SUCCESS),
                        );
                        ui.label(RichText::new("Ban quyen hop le").size(10.0).color(C_MUTED));

                        ui.add_space(8.0);

                        // ── license info card ──
                        egui::Frame::none()
                            .fill(C_CARD)
                            .rounding(8.0)
                            .inner_margin(egui::Margin::symmetric(14.0, 8.0))
                            .show(ui, |ui| {
                                ui.set_width(230.0);
                                if !self.plan_name.is_empty() {
                                    ui.label(RichText::new(&self.plan_name).size(13.0).strong().color(Color32::WHITE));
                                }
                                if !self.expiry_date.is_empty() {
                                    ui.label(
                                        RichText::new(format!("Het han: {}  ({} ngay)", self.expiry_date, self.days_left))
                                            .size(10.0)
                                            .color(C_MUTED),
                                    );
                                }

                                ui.add_space(8.0);

                                // ── ON / OFF ──
                                ui.horizontal(|ui| {
                                    let w = 107.0;
                                    if ui.add(
                                        egui::Button::new(RichText::new("  ON  ").size(13.0).color(Color32::WHITE))
                                            .fill(C_ON).min_size(Vec2::new(w, 26.0)),
                                    ).clicked() { do_on = true; }

                                    ui.add_space(4.0);

                                    if ui.add(
                                        egui::Button::new(RichText::new("  OFF  ").size(13.0).color(Color32::WHITE))
                                            .fill(C_OFF).min_size(Vec2::new(w, 26.0)),
                                    ).clicked() { do_off = true; }
                                });
                            });

                        ui.add_space(8.0);
                        ui.separator();
                        ui.add_space(2.0);
                        ui.label(
                            RichText::new(format!("HWID  {}", &self.hwid[..20]))
                                .size(9.0)
                                .color(Color32::from_rgb(71, 85, 105)),
                        );
                    });
                });

            if do_on  { crate::process_mgr::spawn_all_processes(std::path::Path::new(HETCUU_DIR)); }
            if do_off { crate::process_mgr::terminate_old_processes(); }

            if let Some(at) = self.next_heartbeat_at {
                let remaining = at.saturating_duration_since(Instant::now());
                if remaining.is_zero() { ctx.request_repaint(); }
                else { ctx.request_repaint_after(remaining); }
            }
        }

        fn draw_trial(&mut self, ctx: &egui::Context) {
            let remaining = Duration::from_secs(TRIAL_SESSION_SECS)
                .saturating_sub(self.session_start.elapsed());
            let secs = remaining.as_secs();

            if secs <= TRIAL_WARN_SECS && !self.popup_visible {
                self.popup_visible = true;
                self.popup_start = Some(Instant::now());
            }

            let mut renew = false;
            let mut exit_now = false;
            let mut do_on = false;
            let mut do_off = false;

            egui::CentralPanel::default()
                .frame(egui::Frame::none().fill(C_PANEL))
                .show(ctx, |ui| {
                    ui.set_min_size(ui.available_size());
                    ui.vertical_centered(|ui| {
                        ui.add_space(14.0);

                        ui.label(RichText::new("AntiSupport").size(22.0).strong().color(C_ACCENT));
                        ui.label(RichText::new("Phien dung thu").size(10.0).color(C_MUTED));

                        ui.add_space(8.0);

                        egui::Frame::none()
                            .fill(C_CARD)
                            .rounding(8.0)
                            .inner_margin(egui::Margin::symmetric(14.0, 10.0))
                            .show(ui, |ui| {
                                ui.set_width(230.0);
                                ui.vertical_centered(|ui| {
                                    let col = if secs > 30 { C_SUCCESS }
                                              else if secs > TRIAL_WARN_SECS { Color32::from_rgb(250, 204, 21) }
                                              else { C_DANGER };
                                    ui.label(
                                        RichText::new(format!("{:02}:{:02}", secs / 60, secs % 60))
                                            .size(56.0)
                                            .strong()
                                            .color(col),
                                    );
                                    ui.label(RichText::new("con lai trong phien").size(10.0).color(C_MUTED));
                                });

                                ui.add_space(8.0);

                                ui.horizontal(|ui| {
                                    let w = 107.0;
                                    if ui.add(
                                        egui::Button::new(RichText::new("  ON  ").size(13.0).color(Color32::WHITE))
                                            .fill(C_ON).min_size(Vec2::new(w, 26.0)),
                                    ).clicked() { do_on = true; }
                                    ui.add_space(4.0);
                                    if ui.add(
                                        egui::Button::new(RichText::new("  OFF  ").size(13.0).color(Color32::WHITE))
                                            .fill(C_OFF).min_size(Vec2::new(w, 26.0)),
                                    ).clicked() { do_off = true; }
                                });
                            });

                        ui.add_space(8.0);
                        ui.separator();
                        ui.add_space(2.0);
                        ui.label(
                            RichText::new(format!("HWID  {}", &self.hwid[..20]))
                                .size(9.0)
                                .color(Color32::from_rgb(71, 85, 105)),
                        );
                    });
                });

            // ── renewal popup ──
            if self.popup_visible {
                let countdown = self.popup_start
                    .map(|t| TRIAL_WARN_SECS.saturating_sub(t.elapsed().as_secs()))
                    .unwrap_or(0);

                if countdown == 0 {
                    exit_now = true;
                } else {
                    let mut open = true;
                    egui::Window::new("Phien sap het")
                        .collapsible(false).resizable(false)
                        .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
                        .frame(egui::Frame::window(&ctx.style()).fill(C_CARD).rounding(10.0))
                        .open(&mut open)
                        .show(ctx, |ui| {
                            ui.set_min_width(210.0);
                            ui.vertical_centered(|ui| {
                                ui.add_space(6.0);
                                ui.label(RichText::new("Phien dung thu sap het!").size(12.0).color(Color32::WHITE));
                                ui.add_space(4.0);
                                ui.label(RichText::new(countdown.to_string()).size(60.0).color(C_DANGER));
                                ui.label(RichText::new("giay").size(10.0).color(C_MUTED));
                                ui.add_space(8.0);
                                if ui.add(
                                    egui::Button::new(RichText::new("  Gia han phien  ").size(13.0).color(Color32::WHITE))
                                        .fill(C_ACCENT).min_size(Vec2::new(180.0, 26.0))
                                ).clicked() { renew = true; }
                                ui.add_space(6.0);
                            });
                        });
                    if !open { exit_now = true; }
                }
            }

            if do_on  { crate::process_mgr::spawn_all_processes(std::path::Path::new(HETCUU_DIR)); }
            if do_off { crate::process_mgr::terminate_old_processes(); }
            if renew  { self.renew_trial(); }
            if exit_now { ctx.send_viewport_cmd(egui::ViewportCommand::Close); return; }

            ctx.request_repaint_after(Duration::from_millis(200));
        }
    }

    // ── eframe::App ───────────────────────────────────────────────────────────

    impl eframe::App for TdcApp {
        fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
            self.poll_auth();
            if self.state == State::Session && !self.is_trial {
                self.check_heartbeat(ctx);
                self.poll_heartbeat(ctx);
            }
            match self.state {
                State::Login | State::Authenticating => self.draw_login(ctx),
                State::Session => self.draw_session(ctx),
            }
        }

        fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
            if let Some(token) = self.token.take() {
                self.runtime.block_on(crate::auth::deactivate(token));
            }
            crate::process_mgr::spawn_all_processes(std::path::Path::new(HETCUU_DIR));
        }
    }
}

// ─────────────────────────────── fonts ───────────────────────────────────────

fn setup_fonts(ctx: &eframe::egui::Context) {
    use eframe::egui::{FontData, FontDefinitions, FontFamily};
    let mut fonts = FontDefinitions::default();
    // Segoe UI có đầy đủ Unicode / tiếng Việt, là font hệ thống trên Windows
    for path in [
        "C:/Windows/Fonts/segoeui.ttf",
        "C:/Windows/Fonts/arial.ttf",
    ] {
        if let Ok(data) = std::fs::read(path) {
            fonts.font_data.insert("system_ui".into(), FontData::from_owned(data));
            for family in [FontFamily::Proportional, FontFamily::Monospace] {
                fonts.families.entry(family).or_default().insert(0, "system_ui".into());
            }
            ctx.set_fonts(fonts);
            return;
        }
    }
}

// ─────────────────────────────── expiry check ────────────────────────────────

fn show_expiry_dialog() {
    use std::ffi::OsStr;
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;

    fn wide(s: &str) -> Vec<u16> { OsStr::new(s).encode_wide().chain(once(0u16)).collect() }

    let msg = wide("Phien ban nay da het han.\n\nVui long tai phien ban moi tai hetcuu.com/antisupport");
    let cap = wide("AntiSupport - Het han");
    unsafe {
        winapi::um::winuser::MessageBoxW(
            std::ptr::null_mut(), msg.as_ptr(), cap.as_ptr(),
            winapi::um::winuser::MB_ICONERROR | winapi::um::winuser::MB_OK,
        );
    }
}

fn check_expiry() {
    use chrono::{Local, NaiveDate};
    let today = Local::now().date_naive();
    let expiry = NaiveDate::from_ymd_opt(2027, 6, 30).unwrap();
    if today > expiry { show_expiry_dialog(); std::process::exit(1); }
}

// ─────────────────────────────────── main ────────────────────────────────────

fn main() {
    check_expiry();

    let hwid = hwid::generate().unwrap_or_else(|| "UNKNOWN".to_string());

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build Tokio runtime");

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([280.0, 260.0])
            .with_resizable(false)
            .with_title("AntiSupport"),
        ..Default::default()
    };

    eframe::run_native(
        "antisupport",
        options,
        Box::new(|cc| {
            setup_fonts(&cc.egui_ctx);
            Ok(Box::new(app::TdcApp::new(hwid, runtime)) as Box<dyn eframe::App>)
        }),
    )
    .expect("failed to initialise GUI");
}
