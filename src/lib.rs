use srun::{SrunClient, User};
use std::ffi::{c_char, CStr};

#[no_mangle]
pub extern "C" fn ex_logout(
    auth_server_pointer: *const c_char,
    username_pointer: *const c_char,
    ip_pointer: *const c_char,
) -> bool {
    if auth_server_pointer.is_null() || username_pointer.is_null() || ip_pointer.is_null() {
        return false;
    }

    let auth_server: String = unsafe { CStr::from_ptr(auth_server_pointer) }
        .to_str()
        .expect("Can not read string argument.")
        .to_string();
    let username: String = unsafe { CStr::from_ptr(username_pointer) }
        .to_str()
        .expect("Can not read string argument.")
        .to_string();
    let ip: String = unsafe { CStr::from_ptr(ip_pointer) }
        .to_str()
        .expect("Can not read string argument.")
        .to_string();

    let mut client = SrunClient::new_for_logout(&auth_server, &username, &ip).set_detect_ip(true);

    if let Err(e) = client.logout() {
        println!("Error :{}", e);
        return false;
    }
    return true;
}

#[no_mangle]
pub extern "C" fn ex_login(
    auth_server_pointer: *const c_char,
    username_pointer: *const c_char,
    password_pointer: *const c_char,
    ip_pointer: *const c_char,
) -> bool {
    if auth_server_pointer.is_null()
        || username_pointer.is_null()
        || ip_pointer.is_null()
        || password_pointer.is_null()
    {
        return false;
    }

    let auth_server: String = unsafe { CStr::from_ptr(auth_server_pointer) }
        .to_str()
        .expect("Can not read string argument.")
        .to_string();
    let username: String = unsafe { CStr::from_ptr(username_pointer) }
        .to_str()
        .expect("Can not read string argument.")
        .to_string();
    let password: String = unsafe { CStr::from_ptr(password_pointer) }
        .to_str()
        .expect("Can not read string argument.")
        .to_string();
    let ip: String = unsafe { CStr::from_ptr(ip_pointer) }
        .to_str()
        .expect("Can not read string argument.")
        .to_string();

    let user = User {
        username,
        password,
        ip: Some(ip),
        if_name: None,
    };

    println!("login user: {:#?}", user);

    let mut client = SrunClient::new_from_user(&auth_server, user).set_detect_ip(true);

    if let Err(e) = client.login() {
        println!("Error :{}", e);
        return false;
    }
    return true;
}
