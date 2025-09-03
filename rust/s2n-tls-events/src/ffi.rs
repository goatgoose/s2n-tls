// TODO: autogenerate from s2n-quic-events. will live in generated.rs.

use std::ffi::c_void;
use std::num::NonZeroU64;
use std::time::{Duration, SystemTime};
use s2n_quic_core::event::IntoEvent;
use crate::event::{api, builder, Subscriber};

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct s2n_event_connection_meta {
    pub id: u64,
    pub timestamp_nanoseconds: u64,
}

impl IntoEvent<api::ConnectionMeta> for &s2n_event_connection_meta {
    fn into_event(self) -> api::ConnectionMeta {
        let duration = Duration::from_nanos(self.timestamp_nanoseconds);
        let timestamp = unsafe {
            s2n_quic_core::time::Timestamp::from_duration(duration).into_event()
        };
        api::ConnectionMeta { id: self.id, timestamp }
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct s2n_event_connection_info {}

impl IntoEvent<api::ConnectionInfo> for &s2n_event_connection_info {
    fn into_event(self) -> api::ConnectionInfo {
        api::ConnectionInfo {}
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct s2n_event_application_protocol_information {
    pub alpn: *mut u8,
    pub alpn_len: u32,
}

impl<'a> IntoEvent<api::ApplicationProtocolInformation<'a>> for &s2n_event_application_protocol_information {
    fn into_event(self) -> api::ApplicationProtocolInformation<'a> {
        unsafe {
            api::ApplicationProtocolInformation {
                chosen_application_protocol: std::slice::from_raw_parts(self.alpn, self.alpn_len.try_into().unwrap())
            }
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct s2n_subscriber {
    pub subscriber: *mut c_void,
    pub connection_publisher_new: extern "C" fn(
        subscriber: *mut s2n_subscriber,
        meta: *const s2n_event_connection_meta,
        info: *const s2n_event_connection_info
    ) -> *mut s2n_connection_publisher,
}

pub fn subscriber_to_ptr<S: Subscriber>(subscriber: S) -> *mut s2n_subscriber {
    let boxed_subscriber = Box::new(subscriber);
    let subscriber_ptr = Box::into_raw(boxed_subscriber) as *mut c_void;

    let c_subscriber = s2n_subscriber {
        subscriber: subscriber_ptr,
        connection_publisher_new: connection_publisher_new::<S>,
    };
    let boxed_c_subscriber = Box::new(c_subscriber);
    Box::into_raw(boxed_c_subscriber)
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct s2n_connection_publisher {
    pub subscriber: *mut c_void,
    pub meta: *mut c_void,
    pub context: *mut c_void,
    pub on_application_protocol_information: extern "C" fn(
        s2n_connection_publisher: *mut s2n_connection_publisher,
        event: *mut s2n_event_application_protocol_information
    ),
}

extern "C" fn on_application_protocol_information<S: Subscriber>(
    s2n_connection_publisher: *mut s2n_connection_publisher,
    event: *mut s2n_event_application_protocol_information,
) {
    unsafe {
        let subscriber = &mut *((*s2n_connection_publisher).subscriber as *mut S);
        let meta = &*((*s2n_connection_publisher).meta as *mut api::ConnectionMeta);
        let context = &mut *((*s2n_connection_publisher).context as *mut S::ConnectionContext);

        let event = (&*event).into_event();
        subscriber.on_application_protocol_information(context, meta, &event);
        subscriber.on_connection_event(context, meta, &event);
        subscriber.on_event(meta, &event);
    }
}

extern "C" fn connection_publisher_new<S: Subscriber>(
    c_subscriber: *mut s2n_subscriber,
    meta: *const s2n_event_connection_meta,
    info: *const s2n_event_connection_info,
) -> *mut s2n_connection_publisher {
    let meta = unsafe { (&*meta).into_event() };
    let info = unsafe { &*info }.into_event();
    let subscriber = unsafe { &mut *((*c_subscriber).subscriber as *mut S) };

    let context = subscriber.create_connection_context(&meta, &info);
    let boxed_context = Box::new(context);
    let context_ptr = Box::into_raw(boxed_context) as *mut c_void;

    let meta_box = Box::new(meta);
    let meta_ptr = Box::into_raw(meta_box) as *mut c_void;

    let boxed_subscriber = Box::new(subscriber);
    let subscriber_ptr = Box::into_raw(boxed_subscriber) as *mut c_void;

    let publisher = s2n_connection_publisher {
        subscriber: subscriber_ptr,
        meta: meta_ptr,
        context: context_ptr,
        on_application_protocol_information: on_application_protocol_information::<S>,
    };
    let boxed_publisher = Box::new(publisher);
    Box::into_raw(boxed_publisher)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn s2n_subscriber_connection_publisher_new(
    subscriber: *mut s2n_subscriber,
    meta: *const s2n_event_connection_meta,
    info: *const s2n_event_connection_info
) -> *mut s2n_connection_publisher {
    let subscriber_ref = &*subscriber;
    (subscriber_ref.connection_publisher_new)(subscriber, meta, info)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn s2n_connection_publisher_on_application_protocol_information(
    publisher: *mut s2n_connection_publisher,
    event: *mut s2n_event_application_protocol_information,
) {
    let publisher_ref = &*publisher;
    (publisher_ref.on_application_protocol_information)(publisher, event)
}
