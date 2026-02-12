use std::collections::HashMap;
use std::convert::Infallible;
use std::future::{Ready, ready};
use std::sync::Arc;

use actix_web::body::{BoxBody, EitherBody};
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready};
use actix_web::http::Method;
use actix_web::{Error, FromRequest, HttpMessage, HttpResponse, ResponseError};
use futures_util::future::LocalBoxFuture;
use storage::rbac::Access;

use super::helpers::HttpError;
use crate::common::auth::{AuthError, AuthKeys};

pub struct Auth {
    auth_keys: AuthKeys,
    whitelist: Vec<WhitelistItem>,
    blacklist: Blacklist,
}

impl Auth {
    pub fn new(auth_keys: AuthKeys, whitelist: Vec<WhitelistItem>, blacklist: Blacklist) -> Self {
        Self {
            auth_keys,
            whitelist,
            blacklist,
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for Auth
where
    S: Service<ServiceRequest, Response = ServiceResponse<EitherBody<B, BoxBody>>, Error = Error>
        + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddleware {
            auth_keys: Arc::new(self.auth_keys.clone()),
            whitelist: self.whitelist.clone(),
            blacklist: self.blacklist.clone(),
            service: Arc::new(service),
        }))
    }
}

#[derive(Clone, Eq, PartialEq, Hash)]
pub struct WhitelistItem(pub String, pub PathMode);

impl WhitelistItem {
    pub fn exact<S: Into<String>>(path: S) -> Self {
        Self(path.into(), PathMode::Exact)
    }

    pub fn prefix<S: Into<String>>(path: S) -> Self {
        Self(path.into(), PathMode::Prefix)
    }

    pub fn matches(&self, other: &str) -> bool {
        self.1.check(&self.0, other)
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub enum PathMode {
    /// Path must match exactly
    Exact,
    /// Path must have given prefix
    Prefix,
}

impl PathMode {
    fn check(&self, key: &str, other: &str) -> bool {
        match self {
            Self::Exact => key == other,
            Self::Prefix => other.starts_with(key),
        }
    }
}

#[derive(Clone)]
pub struct Blacklist(HashMap<Method, Vec<Vec<String>>>);

impl Blacklist {
    pub fn matches(&self, method: &Method, path: &str) -> bool {
        let Some(blacklist_patterns) = self.0.get(method) else {
            return false;
        };

        let passed_pattern = path.split('/').collect::<Vec<_>>();

        blacklist_patterns.iter().any(|blacklist_pattern| {
            if blacklist_pattern.len() != passed_pattern.len() {
                return false;
            }

            for (blacklist_part, passed_part) in blacklist_pattern.iter().zip(passed_pattern.iter())
            {
                if blacklist_part != passed_part && blacklist_part != "*" {
                    return false;
                }
            }

            true
        })
    }

    #[cfg(test)]
    fn into_inner(self) -> HashMap<Method, Vec<Vec<String>>> {
        self.0
    }
}

impl TryFrom<Option<&str>> for Blacklist {
    type Error = std::io::Error;

    fn try_from(value: Option<&str>) -> Result<Self, Self::Error> {
        let mut blacklist = HashMap::new();

        if let Some(blacklist_str) = value
            && !blacklist_str.is_empty()
        {
            for pair in blacklist_str.trim().split(',') {
                let mut pair_iter = pair.trim().split(' ');

                let Some(method_str) = pair_iter.next() else {
                    return Err(Self::Error::other(
                        "No method provided for a blacklist item",
                    ));
                };
                let method = Method::from_bytes(method_str.trim().as_bytes()).map_err(|_| {
                    Self::Error::other(format!(
                        "Provided invalid method for a blacklist: {method_str}"
                    ))
                })?;

                let Some(path_str) = pair_iter.next() else {
                    return Err(Self::Error::other("No path provided for a blacklist item"));
                };
                if pair_iter.next().is_some() {
                    return Err(Self::Error::other(
                        "Provided extra parts for a blacklist item",
                    ));
                }

                let item = path_str
                    .trim()
                    .split('/')
                    .map(|s| s.trim().to_string())
                    .collect();

                match blacklist.get_mut(&method) {
                    None => {
                        let paths = vec![item];
                        blacklist.insert(method, paths);
                    }
                    Some(paths) => {
                        paths.push(item);
                    }
                };
            }
        };

        Ok(Blacklist(blacklist))
    }
}

pub struct AuthMiddleware<S> {
    auth_keys: Arc<AuthKeys>,
    /// List of items whitelisted from authentication.
    whitelist: Vec<WhitelistItem>,
    /// List of items blackisted for JWT authentication by configuration.
    blacklist: Blacklist,
    service: Arc<S>,
}

impl<S> AuthMiddleware<S> {
    pub fn is_path_whitelisted(&self, path: &str) -> bool {
        self.whitelist.iter().any(|item| item.matches(path))
    }
}

impl<S, B> Service<ServiceRequest> for AuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<EitherBody<B, BoxBody>>, Error = Error>
        + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let path = req.path();
        if self.is_path_whitelisted(path) {
            return Box::pin(self.service.call(req));
        }

        let auth_keys = self.auth_keys.clone();
        let service = self.service.clone();
        let blacklist_matches = self.blacklist.matches(req.method(), path);
        Box::pin(async move {
            match auth_keys
                .validate_request(
                    |key| req.headers().get(key).and_then(|val| val.to_str().ok()),
                    blacklist_matches,
                )
                .await
            {
                Ok((access, inference_token)) => {
                    let previous = req.extensions_mut().insert::<Access>(access);
                    req.extensions_mut().insert(inference_token);
                    debug_assert!(
                        previous.is_none(),
                        "Previous access object should not exist in the request"
                    );
                    service.call(req).await
                }
                Err(e) => {
                    let resp = match e {
                        AuthError::Unauthorized(e) => HttpResponse::Unauthorized().body(e),
                        AuthError::Forbidden(e) => HttpResponse::Forbidden().body(e),
                        AuthError::StorageError(e) => HttpError::from(e).error_response(),
                    };
                    Ok(req.into_response(resp).map_into_right_body())
                }
            }
        })
    }
}

pub struct ActixAccess(pub Access);

impl FromRequest for ActixAccess {
    type Error = Infallible;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let access = req.extensions_mut().remove::<Access>().unwrap_or_else(|| {
            Access::full("All requests have full by default access when API key is not configured")
        });
        ready(Ok(ActixAccess(access)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blacklist_parsing() {
        let blacklist = Blacklist::try_from(None).unwrap().into_inner();
        assert!(blacklist.is_empty());

        let blacklist = Blacklist::try_from(Some("")).unwrap().into_inner();
        assert!(blacklist.is_empty());

        let blacklist = Blacklist::try_from(Some(
            "GET /debugger, put /cluster/metadata/keys/*, PUT /collections/*/snapshots/recover",
        ))
        .unwrap();
        assert!(blacklist.matches(&Method::GET, "/debugger"));
        assert!(!blacklist.matches(&Method::GET, "/debuggerr"));
        assert!(!blacklist.matches(&Method::POST, "/debugger"));
        assert!(blacklist.matches(&Method::PUT, "/collections/c1/snapshots/recover"));
        assert!(!blacklist.matches(&Method::PUT, "/collections/c1/snapshots/recover/1"));
        assert!(!blacklist.matches(&Method::PUT, "/collections/c1/snapshots"));
    }
}
