fn main() {
    if std::env::var("TARGET").unwrap().contains("windows") {
        let mut res = winres::WindowsResource::new();
        res.set_icon("0qpzu-cm5pv-001.ico");
        res.compile().unwrap();
    }
}