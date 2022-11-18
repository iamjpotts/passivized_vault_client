use std::borrow::Borrow;
use std::fmt::{Display, Formatter};

#[derive(Clone)]
pub struct VaultApiUrl {
    base: String
}

impl Display for VaultApiUrl {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // Because the type name of this struct contains Url, return a plain url.
        write!(f, "{}", self.base)
    }
}

impl VaultApiUrl {

    /// Create a URL reference to a Vault API, which can be used
    /// to create a Vault API client.
    ///
    /// # Example
    ///
    /// ```rust
    /// use passivized_vault_client::client::VaultApiUrl;
    ///
    /// let api_url = VaultApiUrl::new("http://server:8200");
    /// ```
    pub fn new<A>(base: A) -> Self where A: Into<String> {
        VaultApiUrl {
            base: base.into()
        }
    }

    fn at<A: Borrow<str>>(&self, path: A) -> String {
        self.base.clone() + path.borrow()
    }

    pub(crate) fn auth(&self, path: &str) -> String {
        self.at(format!("/v1/sys/auth/{}", path))
    }

    // https://www.vaultproject.io/api-docs/system/init
    pub(crate) fn init(&self) -> String {
        self.at("/v1/sys/init")
    }

    pub(crate) fn mount(&self, path: &str) -> String {
        format!("{}/{}", self.mounts(), urlencoding::encode(path))
    }

    pub(crate) fn mounts(&self) -> String {
        self.at("/v1/sys/mounts")
    }

    pub(crate) fn plugins_catalog(&self) -> String {
        self.at("/v1/sys/plugins/catalog")
    }

    pub(crate) fn policies(&self) -> VaultPoliciesApiUrl {
        VaultPoliciesApiUrl {
            url: self.clone()
        }
    }

    pub fn status(&self) -> String {
        self.at("/v1/sys/seal-status")
    }

    pub(crate) fn token(&self, path: &str) -> VaultAuthTokenApiUrl {
        VaultAuthTokenApiUrl {
            url: self.clone(),
            path: path.into()
        }
    }

    // https://www.vaultproject.io/api-docs/secret/transit
    pub(crate) fn transit(&self, mount_path: &str, name: &str) -> String {
        self.at(format!("/v1/{}/keys/{}", mount_path, urlencoding::encode(name)))
    }

    // https://www.vaultproject.io/api-docs/system/unseal
    pub(crate) fn unseal(&self) -> String {
        self.at("/v1/sys/unseal")
    }

    pub(crate) fn userpass(&self, path: &str) -> VaultAuthUserpassApiUrl {
        VaultAuthUserpassApiUrl {
            url: self.clone(),
            path: path.to_string()
        }
    }
}

pub(crate) struct VaultAuthTokenApiUrl {
    url: VaultApiUrl,
    path: String
}

impl VaultAuthTokenApiUrl {

    pub(crate) fn create(&self) -> String {
        self.url.at(format!("/v1/auth/{}/create", self.path))
    }

    pub(crate) fn lookup_self(&self) -> String {
        self.url.at(format!("/v1/auth/{}/lookup-self", self.path))
    }

}

pub(crate) struct VaultAuthUserpassApiUrl {
    url: VaultApiUrl,
    path: String
}

impl VaultAuthUserpassApiUrl {

    pub(crate) fn list(&self) -> String {
        self.url.at(format!("/v1/auth/{}/users", self.path))
    }

    pub(crate) fn login<U: Borrow<str>>(&self, username: U) -> String {
        self.url.at(format!("/v1/auth/{}/login/{}", self.path, username.borrow()))
    }

    pub(crate) fn user<U: Borrow<str>>(&self, username: U) -> String {
        self.url.at(format!("/v1/auth/{}/users/{}", self.path, username.borrow()))
    }

    pub(crate) fn update<U: Borrow<str>>(&self, username: U) -> String {
        self.user(username) + "/password"
    }
}

pub(crate) struct VaultPoliciesApiUrl {
    url: VaultApiUrl
}

impl VaultPoliciesApiUrl {

    pub(crate) fn acl(&self) -> VaultPoliciesAclApiUrl {
        VaultPoliciesAclApiUrl {
            url: self.url.clone()
        }
    }
}

pub(crate) struct VaultPoliciesAclApiUrl {
    url: VaultApiUrl
}

impl VaultPoliciesAclApiUrl {

    pub(crate) fn list(&self) -> String {
        self.url.at("/v1/sys/policies/acl")
    }

    pub(crate) fn item(&self, name: &str) -> String {
        format!("{}/{}", self.list(), name)
    }

}

#[cfg(test)]
mod test_vault_api_url {
    use super::VaultApiUrl;

    #[test]
    fn display() {
        let url = VaultApiUrl::new("https://testuri.org");

        assert_eq!("https://testuri.org", format!("{}", url));
    }

    #[test]
    fn plugins_catalog() {
        let url = VaultApiUrl::new("http://z");

        assert_eq!("http://z/v1/sys/plugins/catalog", url.plugins_catalog());
    }

    #[test]
    fn mounts() {
        let url = VaultApiUrl::new("http://foo");

        assert_eq!("http://foo/v1/sys/seal-status", url.status());
    }

    #[test]
    fn status() {
        let url = VaultApiUrl::new("https://bar:123");

        assert_eq!("https://bar:123/v1/sys/mounts", url.mounts());
    }

    #[test]
    fn transit() {
        let url = VaultApiUrl::new("");

        assert_eq!("/v1/a/keys/b", url.transit("a", "b"));
    }

    #[cfg(test)]
    mod policies {

        mod acl {
            use crate::client::VaultApiUrl;

            #[test]
            fn item() {
                let url = VaultApiUrl::new("");

                assert_eq!("/v1/sys/policies/acl/foo", url.policies().acl().item("foo"));
            }

            #[test]
            fn list() {
                let url = VaultApiUrl::new("");

                assert_eq!("/v1/sys/policies/acl", url.policies().acl().list());
            }
        }

    }

    #[cfg(test)]
    mod token {
        use crate::client::VaultApiUrl;

        #[test]
        fn create() {
            let url = VaultApiUrl::new("");

            assert_eq!("/v1/auth/token/create", url.token("token").create());
        }

        #[test]
        fn lookup_self() {
            let url = VaultApiUrl::new("");

            assert_eq!("/v1/auth/foo/lookup-self", url.token("foo").lookup_self());
        }
    }

    #[test]
    fn userpass_login() {
        let url = VaultApiUrl::new("");

        assert_eq!("/v1/auth/x/login/mary", url.userpass("x").login("mary"));
    }

    #[test]
    fn userpass_user() {
        let url = VaultApiUrl::new("");

        assert_eq!("/v1/auth/a/b/users/john", url.userpass("a/b").user("john"));
    }
}
