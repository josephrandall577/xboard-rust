//! User authentication shared by the multi-user services.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, RwLock};

use crate::error::{self, ErrorCode};
use crate::net::Context;
use crate::request::Request;

pub(crate) type Authenticator = dyn Fn(&Context, &Request) -> io::Result<Context> + Send + Sync;

pub(crate) type UserMap<U> = Arc<RwLock<Arc<HashMap<Vec<u8>, U>>>>;

/// `UpdateUsers` validation shared by the v5 and v6 multi-user services.
pub(crate) fn build_user_map<U: Clone>(users: Vec<U>, user_keys: Vec<Vec<u8>>) -> io::Result<HashMap<Vec<u8>, U>> {
    if users.len() != user_keys.len() {
        return Err(error::new_invalid("snell: user/key count mismatch"));
    }
    if users.is_empty() {
        return Err(ErrorCode::NoUsers.into());
    }
    let mut user_map = HashMap::with_capacity(users.len());
    for (user, key) in users.into_iter().zip(user_keys) {
        if key.is_empty() {
            return Err(ErrorCode::BadUserKey.into());
        }
        if key.len() > 255 {
            return Err(error::new_invalid("snell: user key too long"));
        }
        if user_map.contains_key(&key) {
            return Err(ErrorCode::DuplicateUserKey.into());
        }
        user_map.insert(key, user);
    }
    Ok(user_map)
}

/// The authenticator shared by the v5 and v6 multi-user services.
pub(crate) fn user_authenticator<U: Clone + Send + Sync + 'static>(users: UserMap<U>) -> Box<Authenticator> {
    Box::new(move |ctx: &Context, request: &Request| {
        let users = users.read().unwrap().clone();
        match users.get(&request.client_id) {
            Some(user) => Ok(ctx.clone().with_user(user.clone())),
            None => Err(ErrorCode::BadUserKey.into()),
        }
    })
}
