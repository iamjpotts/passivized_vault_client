
pub mod vault {
    use const_str::concat;

    pub const NAME: &str = "vault";
    pub const TAG: &str = "1.12.2";
    pub const IMAGE: &str = concat!(NAME, ":", TAG);
}