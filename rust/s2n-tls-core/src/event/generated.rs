// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// DO NOT MODIFY THIS FILE
// This file was generated with the `s2n-events` crate and any required
// changes should be made there.

#![allow(clippy::needless_lifetimes)]
use super::*;
pub(crate) mod metrics;
pub mod api {
    #![doc = r" This module contains events that are emitted to the [`Subscriber`](crate::event::Subscriber)"]
    use super::*;
    #[allow(unused_imports)]
    use crate::event::metrics::aggregate;
    pub use traits::Subscriber;
    #[derive(Clone, Debug)]
    #[non_exhaustive]
    pub struct ConnectionMeta {
        pub id: u64,
        pub timestamp: Timestamp,
    }
    #[cfg(any(test, feature = "testing"))]
    impl crate::event::snapshot::Fmt for ConnectionMeta {
        fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
            let mut fmt = fmt.debug_struct("ConnectionMeta");
            fmt.field("id", &self.id);
            fmt.field("timestamp", &self.timestamp);
            fmt.finish()
        }
    }
    #[derive(Clone, Debug)]
    #[non_exhaustive]
    pub struct EndpointMeta {}
    #[cfg(any(test, feature = "testing"))]
    impl crate::event::snapshot::Fmt for EndpointMeta {
        fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
            let mut fmt = fmt.debug_struct("EndpointMeta");
            fmt.finish()
        }
    }
    #[derive(Clone, Debug)]
    #[non_exhaustive]
    pub struct ConnectionInfo {}
    #[cfg(any(test, feature = "testing"))]
    impl crate::event::snapshot::Fmt for ConnectionInfo {
        fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
            let mut fmt = fmt.debug_struct("ConnectionInfo");
            fmt.finish()
        }
    }
    #[derive(Clone, Debug)]
    #[non_exhaustive]
    pub enum Subject {
        #[non_exhaustive]
        Endpoint {},
        #[non_exhaustive]
        Connection { id: u64 },
    }
    impl aggregate::AsVariant for Subject {
        const VARIANTS: &'static [aggregate::info::Variant] = &[
            aggregate::info::variant::Builder {
                name: aggregate::info::Str::new("ENDPOINT\0"),
                id: 0usize,
            }
            .build(),
            aggregate::info::variant::Builder {
                name: aggregate::info::Str::new("CONNECTION\0"),
                id: 1usize,
            }
            .build(),
        ];
        #[inline]
        fn variant_idx(&self) -> usize {
            match self {
                Self::Endpoint { .. } => 0usize,
                Self::Connection { .. } => 1usize,
            }
        }
    }
    #[derive(Clone, Debug)]
    #[non_exhaustive]
    pub struct ByteArrayEvent<'a> {
        pub data: &'a [u8],
    }
    #[cfg(any(test, feature = "testing"))]
    impl<'a> crate::event::snapshot::Fmt for ByteArrayEvent<'a> {
        fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
            let mut fmt = fmt.debug_struct("ByteArrayEvent");
            fmt.field("data", &self.data);
            fmt.finish()
        }
    }
    impl<'a> Event for ByteArrayEvent<'a> {
        const NAME: &'static str = "byte_array_event";
    }
    impl IntoEvent<builder::ConnectionMeta> for *const c_ffi::s2n_event_connection_meta {
        fn into_event(self) -> builder::ConnectionMeta {
            let event = unsafe { &*self };
            let duration = Duration::from_nanos(event.timestamp);
            let timestamp =
                unsafe { s2n_quic_core::time::Timestamp::from_duration(duration).into_event() };
            builder::ConnectionMeta {
                id: event.id,
                timestamp,
            }
        }
    }
    impl IntoEvent<builder::ConnectionInfo> for *const c_ffi::s2n_event_connection_info {
        fn into_event(self) -> builder::ConnectionInfo {
            builder::ConnectionInfo {}
        }
    }
    impl<'a> IntoEvent<builder::ByteArrayEvent<'a>> for *const c_ffi::s2n_event_byte_array {
        fn into_event(self) -> builder::ByteArrayEvent<'a> {
            unsafe {
                let event = &*self;
                builder::ByteArrayEvent {
                    data: std::slice::from_raw_parts(
                        event.data,
                        event.data_len.try_into().unwrap(),
                    ),
                }
            }
        }
    }
}
pub mod tracing {
    #![doc = r" This module contains event integration with [`tracing`](https://docs.rs/tracing)"]
    use super::api;
    #[doc = r" Emits events with [`tracing`](https://docs.rs/tracing)"]
    #[derive(Clone, Debug)]
    pub struct Subscriber {
        root: tracing::Span,
    }
    impl Default for Subscriber {
        fn default() -> Self {
            let root =
                tracing :: span ! (target : "tls_test" , tracing :: Level :: DEBUG , "tls_test");
            Self { root }
        }
    }
    impl Subscriber {
        fn parent<M: crate::event::Meta>(&self, _meta: &M) -> Option<tracing::Id> {
            self.root.id()
        }
    }
    impl super::Subscriber for Subscriber {
        type ConnectionContext = tracing::Span;
        fn create_connection_context(
            &mut self,
            meta: &api::ConnectionMeta,
            _info: &api::ConnectionInfo,
        ) -> Self::ConnectionContext {
            let parent = self.parent(meta);
            tracing :: span ! (target : "s2n_tls_core" , parent : parent , tracing :: Level :: DEBUG , "conn" , id = meta . id)
        }
        #[inline]
        fn on_byte_array_event(
            &mut self,
            context: &mut Self::ConnectionContext,
            _meta: &api::ConnectionMeta,
            event: &api::ByteArrayEvent,
        ) {
            let id = context.id();
            let api::ByteArrayEvent { data } = event;
            tracing :: event ! (target : "byte_array_event" , parent : id , tracing :: Level :: DEBUG , { data = tracing :: field :: debug (data) });
        }
    }
}
pub mod builder {
    use super::*;
    #[derive(Clone, Debug)]
    pub struct ConnectionMeta {
        pub id: u64,
        pub timestamp: Timestamp,
    }
    impl IntoEvent<api::ConnectionMeta> for ConnectionMeta {
        #[inline]
        fn into_event(self) -> api::ConnectionMeta {
            let ConnectionMeta { id, timestamp } = self;
            api::ConnectionMeta {
                id: id.into_event(),
                timestamp: timestamp.into_event(),
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct EndpointMeta {}
    impl IntoEvent<api::EndpointMeta> for EndpointMeta {
        #[inline]
        fn into_event(self) -> api::EndpointMeta {
            let EndpointMeta {} = self;
            api::EndpointMeta {}
        }
    }
    #[derive(Clone, Debug)]
    pub struct ConnectionInfo {}
    impl IntoEvent<api::ConnectionInfo> for ConnectionInfo {
        #[inline]
        fn into_event(self) -> api::ConnectionInfo {
            let ConnectionInfo {} = self;
            api::ConnectionInfo {}
        }
    }
    #[derive(Clone, Debug)]
    pub enum Subject {
        Endpoint,
        Connection { id: u64 },
    }
    impl IntoEvent<api::Subject> for Subject {
        #[inline]
        fn into_event(self) -> api::Subject {
            use api::Subject::*;
            match self {
                Self::Endpoint => Endpoint {},
                Self::Connection { id } => Connection {
                    id: id.into_event(),
                },
            }
        }
    }
    #[derive(Clone, Debug)]
    pub struct ByteArrayEvent<'a> {
        pub data: &'a [u8],
    }
    impl<'a> IntoEvent<api::ByteArrayEvent<'a>> for ByteArrayEvent<'a> {
        #[inline]
        fn into_event(self) -> api::ByteArrayEvent<'a> {
            let ByteArrayEvent { data } = self;
            api::ByteArrayEvent {
                data: data.into_event(),
            }
        }
    }
}
pub use traits::*;
mod traits {
    use super::*;
    use crate::event::Meta;
    use core::fmt;
    use s2n_quic_core::query;
    #[doc = r" Allows for events to be subscribed to"]
    pub trait Subscriber: 'static + Send {
        #[doc = r" An application provided type associated with each connection."]
        #[doc = r""]
        #[doc = r" The context provides a mechanism for applications to provide a custom type"]
        #[doc = r" and update it on each event, e.g. computing statistics. Each event"]
        #[doc = r" invocation (e.g. [`Subscriber::on_packet_sent`]) also provides mutable"]
        #[doc = r" access to the context `&mut ConnectionContext` and allows for updating the"]
        #[doc = r" context."]
        #[doc = r""]
        #[doc = r" ```no_run"]
        #[doc = r" # mod s2n_quic { pub mod provider { pub mod event {"]
        #[doc = r" #     pub use s2n_quic_core::event::{api as events, api::ConnectionInfo, api::ConnectionMeta, Subscriber};"]
        #[doc = r" # }}}"]
        #[doc = r" use s2n_quic::provider::event::{"]
        #[doc = r"     ConnectionInfo, ConnectionMeta, Subscriber, events::PacketSent"]
        #[doc = r" };"]
        #[doc = r""]
        #[doc = r" pub struct MyEventSubscriber;"]
        #[doc = r""]
        #[doc = r" pub struct MyEventContext {"]
        #[doc = r"     packet_sent: u64,"]
        #[doc = r" }"]
        #[doc = r""]
        #[doc = r" impl Subscriber for MyEventSubscriber {"]
        #[doc = r"     type ConnectionContext = MyEventContext;"]
        #[doc = r""]
        #[doc = r"     fn create_connection_context("]
        #[doc = r"         &mut self, _meta: &ConnectionMeta,"]
        #[doc = r"         _info: &ConnectionInfo,"]
        #[doc = r"     ) -> Self::ConnectionContext {"]
        #[doc = r"         MyEventContext { packet_sent: 0 }"]
        #[doc = r"     }"]
        #[doc = r""]
        #[doc = r"     fn on_packet_sent("]
        #[doc = r"         &mut self,"]
        #[doc = r"         context: &mut Self::ConnectionContext,"]
        #[doc = r"         _meta: &ConnectionMeta,"]
        #[doc = r"         _event: &PacketSent,"]
        #[doc = r"     ) {"]
        #[doc = r"         context.packet_sent += 1;"]
        #[doc = r"     }"]
        #[doc = r" }"]
        #[doc = r"  ```"]
        type ConnectionContext: 'static + Send;
        #[doc = r" Creates a context to be passed to each connection-related event"]
        fn create_connection_context(
            &mut self,
            meta: &api::ConnectionMeta,
            info: &api::ConnectionInfo,
        ) -> Self::ConnectionContext;
        #[doc = "Called when the `ByteArrayEvent` event is triggered"]
        #[inline]
        fn on_byte_array_event(
            &mut self,
            context: &mut Self::ConnectionContext,
            meta: &api::ConnectionMeta,
            event: &api::ByteArrayEvent,
        ) {
            let _ = context;
            let _ = meta;
            let _ = event;
        }
        #[doc = r" Called for each event that relates to the endpoint and all connections"]
        #[inline]
        fn on_event<M: Meta, E: Event>(&mut self, meta: &M, event: &E) {
            let _ = meta;
            let _ = event;
        }
        #[doc = r" Called for each event that relates to a connection"]
        #[inline]
        fn on_connection_event<E: Event>(
            &mut self,
            context: &mut Self::ConnectionContext,
            meta: &api::ConnectionMeta,
            event: &E,
        ) {
            let _ = context;
            let _ = meta;
            let _ = event;
        }
        #[doc = r" Used for querying the `Subscriber::ConnectionContext` on a Subscriber"]
        #[inline]
        fn query(
            context: &Self::ConnectionContext,
            query: &mut dyn query::Query,
        ) -> query::ControlFlow {
            query.execute(context)
        }
        #[doc = r" Used for querying and mutating the `Subscriber::ConnectionContext` on a Subscriber"]
        #[inline]
        fn query_mut(
            context: &mut Self::ConnectionContext,
            query: &mut dyn query::QueryMut,
        ) -> query::ControlFlow {
            query.execute_mut(context)
        }
    }
    #[doc = r" Subscriber is implemented for a 2-element tuple to make it easy to compose multiple"]
    #[doc = r" subscribers."]
    impl<A, B> Subscriber for (A, B)
    where
        A: Subscriber,
        B: Subscriber,
    {
        type ConnectionContext = (A::ConnectionContext, B::ConnectionContext);
        #[inline]
        fn create_connection_context(
            &mut self,
            meta: &api::ConnectionMeta,
            info: &api::ConnectionInfo,
        ) -> Self::ConnectionContext {
            (
                self.0.create_connection_context(meta, info),
                self.1.create_connection_context(meta, info),
            )
        }
        #[inline]
        fn on_byte_array_event(
            &mut self,
            context: &mut Self::ConnectionContext,
            meta: &api::ConnectionMeta,
            event: &api::ByteArrayEvent,
        ) {
            (self.0).on_byte_array_event(&mut context.0, meta, event);
            (self.1).on_byte_array_event(&mut context.1, meta, event);
        }
        #[inline]
        fn on_event<M: Meta, E: Event>(&mut self, meta: &M, event: &E) {
            self.0.on_event(meta, event);
            self.1.on_event(meta, event);
        }
        #[inline]
        fn on_connection_event<E: Event>(
            &mut self,
            context: &mut Self::ConnectionContext,
            meta: &api::ConnectionMeta,
            event: &E,
        ) {
            self.0.on_connection_event(&mut context.0, meta, event);
            self.1.on_connection_event(&mut context.1, meta, event);
        }
        #[inline]
        fn query(
            context: &Self::ConnectionContext,
            query: &mut dyn query::Query,
        ) -> query::ControlFlow {
            query
                .execute(context)
                .and_then(|| A::query(&context.0, query))
                .and_then(|| B::query(&context.1, query))
        }
        #[inline]
        fn query_mut(
            context: &mut Self::ConnectionContext,
            query: &mut dyn query::QueryMut,
        ) -> query::ControlFlow {
            query
                .execute_mut(context)
                .and_then(|| A::query_mut(&mut context.0, query))
                .and_then(|| B::query_mut(&mut context.1, query))
        }
    }
    pub trait EndpointPublisher {
        #[doc = r" Returns the QUIC version, if any"]
        fn quic_version(&self) -> Option<u32>;
    }
    pub struct EndpointPublisherSubscriber<'a, Sub: Subscriber> {
        meta: api::EndpointMeta,
        quic_version: Option<u32>,
        subscriber: &'a mut Sub,
    }
    impl<'a, Sub: Subscriber> fmt::Debug for EndpointPublisherSubscriber<'a, Sub> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.debug_struct("ConnectionPublisherSubscriber")
                .field("meta", &self.meta)
                .field("quic_version", &self.quic_version)
                .finish()
        }
    }
    impl<'a, Sub: Subscriber> EndpointPublisherSubscriber<'a, Sub> {
        #[inline]
        pub fn new(
            meta: builder::EndpointMeta,
            quic_version: Option<u32>,
            subscriber: &'a mut Sub,
        ) -> Self {
            Self {
                meta: meta.into_event(),
                quic_version,
                subscriber,
            }
        }
    }
    impl<'a, Sub: Subscriber> EndpointPublisher for EndpointPublisherSubscriber<'a, Sub> {
        #[inline]
        fn quic_version(&self) -> Option<u32> {
            self.quic_version
        }
    }
    pub trait ConnectionPublisher {
        #[doc = "Publishes a `ByteArrayEvent` event to the publisher's subscriber"]
        fn on_byte_array_event(&mut self, event: builder::ByteArrayEvent);
        #[doc = r" Returns the QUIC version negotiated for the current connection, if any"]
        fn quic_version(&self) -> u32;
        #[doc = r" Returns the [`Subject`] for the current publisher"]
        fn subject(&self) -> api::Subject;
    }
    pub struct ConnectionPublisherSubscriber<'a, Sub: Subscriber> {
        meta: api::ConnectionMeta,
        quic_version: u32,
        subscriber: &'a mut Sub,
        context: &'a mut Sub::ConnectionContext,
    }
    impl<'a, Sub: Subscriber> fmt::Debug for ConnectionPublisherSubscriber<'a, Sub> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.debug_struct("ConnectionPublisherSubscriber")
                .field("meta", &self.meta)
                .field("quic_version", &self.quic_version)
                .finish()
        }
    }
    impl<'a, Sub: Subscriber> ConnectionPublisherSubscriber<'a, Sub> {
        #[inline]
        pub fn new(
            meta: builder::ConnectionMeta,
            quic_version: u32,
            subscriber: &'a mut Sub,
            context: &'a mut Sub::ConnectionContext,
        ) -> Self {
            Self {
                meta: meta.into_event(),
                quic_version,
                subscriber,
                context,
            }
        }
    }
    impl<'a, Sub: Subscriber> ConnectionPublisher for ConnectionPublisherSubscriber<'a, Sub> {
        #[inline]
        fn on_byte_array_event(&mut self, event: builder::ByteArrayEvent) {
            let event = event.into_event();
            self.subscriber
                .on_byte_array_event(self.context, &self.meta, &event);
            self.subscriber
                .on_connection_event(self.context, &self.meta, &event);
            self.subscriber.on_event(&self.meta, &event);
        }
        #[inline]
        fn quic_version(&self) -> u32 {
            self.quic_version
        }
        #[inline]
        fn subject(&self) -> api::Subject {
            self.meta.subject()
        }
    }
}
pub mod c_ffi {
    use super::*;
    use std::ffi::*;
    #[allow(non_camel_case_types)]
    pub struct s2n_event_subscriber {
        subscriber_ptr: *mut c_void,
        connection_publisher_new: fn(
            s2n_event_subscriber_ptr: *mut s2n_event_subscriber,
            meta_ptr: *const s2n_event_connection_meta,
            info_ptr: *const s2n_event_connection_info,
        ) -> *mut s2n_event_connection_publisher,
        free: fn(s2n_event_subscriber_ptr: *mut s2n_event_subscriber) -> c_int,
    }
    impl s2n_event_subscriber {
        fn from_ptr<'a>(s2n_event_subscriber_ptr: *mut s2n_event_subscriber) -> &'a mut Self {
            unsafe { &mut *s2n_event_subscriber_ptr }
        }
        fn subscriber<S: Subscriber>(&self) -> &mut S {
            let subscriber = self.subscriber_ptr as *mut S;
            unsafe { &mut *subscriber }
        }
        fn free<S: Subscriber>(s2n_event_subscriber_ptr: *mut s2n_event_subscriber) -> c_int {
            unsafe {
                let subscriber_box = Box::from_raw(s2n_event_subscriber_ptr);
                let _ = Box::from_raw(subscriber_box.subscriber_ptr as *mut S);
            }
            0
        }
        pub fn new<S: Subscriber>(subscriber: S) -> *mut Self {
            let subscriber_ptr = Box::into_raw(Box::new(subscriber)) as *mut c_void;
            Box::into_raw(Box::new(s2n_event_subscriber {
                subscriber_ptr,
                connection_publisher_new: s2n_event_connection_publisher::new::<S>,
                free: s2n_event_subscriber::free::<S>,
            }))
        }
    }
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn s2n_event_subscriber_free(
        subscriber: *mut s2n_event_subscriber,
    ) -> c_int {
        let subscriber_ref = &*subscriber;
        (subscriber_ref.free)(subscriber);
        0
    }
    #[allow(non_camel_case_types)]
    pub struct s2n_event_connection_publisher {
        connection_publisher_subscriber_ptr: *mut c_void,
        connection_context_ptr: *mut c_void,
        free: fn(s2n_event_connection_publisher_ptr: *mut s2n_event_connection_publisher) -> c_int,
        on_byte_array_event: fn(
            s2n_event_connection_publisher_ptr: *mut s2n_event_connection_publisher,
            event_ptr: *const s2n_event_byte_array,
        ),
    }
    impl s2n_event_connection_publisher {
        fn connection_publisher_subscriber<S: Subscriber>(
            &self,
        ) -> &mut ConnectionPublisherSubscriber<'_, S> {
            let publisher = self.connection_publisher_subscriber_ptr;
            let publisher = publisher as *mut ConnectionPublisherSubscriber<S>;
            unsafe { &mut *publisher }
        }
        fn free<S: Subscriber>(
            s2n_event_connection_publisher_ptr: *mut s2n_event_connection_publisher,
        ) -> c_int {
            unsafe {
                let publisher_box = Box::from_raw(s2n_event_connection_publisher_ptr);
                let _ = Box::from_raw(
                    publisher_box.connection_context_ptr as *mut S::ConnectionContext,
                );
                let _ = Box::from_raw(
                    publisher_box.connection_publisher_subscriber_ptr
                        as *mut ConnectionPublisherSubscriber<S>,
                );
            }
            0
        }
        fn new<S: Subscriber>(
            s2n_event_subscriber_ptr: *mut s2n_event_subscriber,
            meta_ptr: *const s2n_event_connection_meta,
            info_ptr: *const s2n_event_connection_info,
        ) -> *mut s2n_event_connection_publisher {
            let meta = meta_ptr.into_event();
            let info = info_ptr.into_event();
            let subscriber = {
                let event_subscriber = s2n_event_subscriber::from_ptr(s2n_event_subscriber_ptr);
                event_subscriber.subscriber::<S>()
            };
            let connection_context_ptr =
                Box::into_raw(Box::new(subscriber.create_connection_context(
                    &meta.clone().into_event(),
                    &info.clone().into_event(),
                ))) as *mut c_void;
            let connection_publisher_subscriber_ptr = {
                let context_ref =
                    unsafe { &mut *(connection_context_ptr as *mut S::ConnectionContext) };
                Box::into_raw(Box::new(ConnectionPublisherSubscriber::new(
                    meta,
                    0,
                    subscriber,
                    context_ref,
                ))) as *mut c_void
            };
            Box::into_raw(Box::new(s2n_event_connection_publisher {
                connection_publisher_subscriber_ptr,
                connection_context_ptr: connection_context_ptr,
                free: s2n_event_connection_publisher::free::<S>,
                on_byte_array_event: |publisher, event| {
                    let publisher = unsafe { (*publisher).connection_publisher_subscriber::<S>() };
                    publisher.on_byte_array_event(event.into_event());
                },
            }))
        }
    }
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn s2n_event_connection_publisher_new(
        subscriber: *mut s2n_event_subscriber,
        meta: *const s2n_event_connection_meta,
        info: *const s2n_event_connection_info,
    ) -> *mut s2n_event_connection_publisher {
        let subscriber_ref = &*subscriber;
        (subscriber_ref.connection_publisher_new)(subscriber, meta, info)
    }
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn s2n_event_connection_publisher_free(
        publisher: *mut s2n_event_connection_publisher,
    ) -> c_int {
        let publisher_ref = &*publisher;
        (publisher_ref.free)(publisher)
    }
    #[repr(C)]
    #[allow(non_camel_case_types)]
    pub struct s2n_event_connection_meta {
        pub id: u64,
        pub timestamp: u64,
    }
    #[repr(C)]
    #[allow(non_camel_case_types)]
    pub struct s2n_event_connection_info {}
    #[repr(C)]
    #[allow(non_camel_case_types)]
    pub struct s2n_event_byte_array {
        pub data: *mut u8,
        pub data_len: u32,
    }
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn s2n_event_connection_publisher_on_byte_array_event(
        publisher: *mut s2n_event_connection_publisher,
        event: *const s2n_event_byte_array,
    ) -> c_int {
        let publisher_ref = &*publisher;
        (publisher_ref.on_byte_array_event)(publisher, event);
        0
    }
}
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use super::*;
    use crate::event::snapshot::Location;
    pub mod endpoint {
        use super::*;
        pub struct Subscriber {
            location: Option<Location>,
            output: Vec<String>,
        }
        impl Drop for Subscriber {
            fn drop(&mut self) {
                if std::thread::panicking() {
                    return;
                }
                if let Some(location) = self.location.as_ref() {
                    location.snapshot_log(&self.output);
                }
            }
        }
        impl Subscriber {
            #[doc = r" Creates a subscriber with snapshot assertions enabled"]
            #[track_caller]
            pub fn snapshot() -> Self {
                let mut sub = Self::no_snapshot();
                sub.location = Location::from_thread_name();
                sub
            }
            #[doc = r" Creates a subscriber with snapshot assertions enabled"]
            #[track_caller]
            pub fn named_snapshot<Name: core::fmt::Display>(name: Name) -> Self {
                let mut sub = Self::no_snapshot();
                sub.location = Some(Location::new(name));
                sub
            }
            #[doc = r" Creates a subscriber with snapshot assertions disabled"]
            pub fn no_snapshot() -> Self {
                Self {
                    location: None,
                    output: Default::default(),
                }
            }
        }
        impl super::super::Subscriber for Subscriber {
            type ConnectionContext = ();
            fn create_connection_context(
                &mut self,
                _meta: &api::ConnectionMeta,
                _info: &api::ConnectionInfo,
            ) -> Self::ConnectionContext {
            }
        }
    }
    #[derive(Debug)]
    pub struct Subscriber {
        location: Option<Location>,
        output: Vec<String>,
        pub byte_array_event: u64,
    }
    impl Drop for Subscriber {
        fn drop(&mut self) {
            if std::thread::panicking() {
                return;
            }
            if let Some(location) = self.location.as_ref() {
                location.snapshot_log(&self.output);
            }
        }
    }
    impl Subscriber {
        #[doc = r" Creates a subscriber with snapshot assertions enabled"]
        #[track_caller]
        pub fn snapshot() -> Self {
            let mut sub = Self::no_snapshot();
            sub.location = Location::from_thread_name();
            sub
        }
        #[doc = r" Creates a subscriber with snapshot assertions enabled"]
        #[track_caller]
        pub fn named_snapshot<Name: core::fmt::Display>(name: Name) -> Self {
            let mut sub = Self::no_snapshot();
            sub.location = Some(Location::new(name));
            sub
        }
        #[doc = r" Creates a subscriber with snapshot assertions disabled"]
        pub fn no_snapshot() -> Self {
            Self {
                location: None,
                output: Default::default(),
                byte_array_event: 0,
            }
        }
    }
    impl super::Subscriber for Subscriber {
        type ConnectionContext = ();
        fn create_connection_context(
            &mut self,
            _meta: &api::ConnectionMeta,
            _info: &api::ConnectionInfo,
        ) -> Self::ConnectionContext {
        }
        fn on_byte_array_event(
            &mut self,
            _context: &mut Self::ConnectionContext,
            meta: &api::ConnectionMeta,
            event: &api::ByteArrayEvent,
        ) {
            self.byte_array_event += 1;
            if self.location.is_some() {
                let meta = crate::event::snapshot::Fmt::to_snapshot(meta);
                let event = crate::event::snapshot::Fmt::to_snapshot(event);
                let out = format!("{meta:?} {event:?}");
                self.output.push(out);
            }
        }
    }
    #[derive(Debug)]
    pub struct Publisher {
        location: Option<Location>,
        output: Vec<String>,
        pub byte_array_event: u64,
    }
    impl Publisher {
        #[doc = r" Creates a publisher with snapshot assertions enabled"]
        #[track_caller]
        pub fn snapshot() -> Self {
            let mut sub = Self::no_snapshot();
            sub.location = Location::from_thread_name();
            sub
        }
        #[doc = r" Creates a subscriber with snapshot assertions enabled"]
        #[track_caller]
        pub fn named_snapshot<Name: core::fmt::Display>(name: Name) -> Self {
            let mut sub = Self::no_snapshot();
            sub.location = Some(Location::new(name));
            sub
        }
        #[doc = r" Creates a publisher with snapshot assertions disabled"]
        pub fn no_snapshot() -> Self {
            Self {
                location: None,
                output: Default::default(),
                byte_array_event: 0,
            }
        }
    }
    impl super::EndpointPublisher for Publisher {
        fn quic_version(&self) -> Option<u32> {
            Some(1)
        }
    }
    impl super::ConnectionPublisher for Publisher {
        fn on_byte_array_event(&mut self, event: builder::ByteArrayEvent) {
            self.byte_array_event += 1;
            let event = event.into_event();
            if self.location.is_some() {
                let event = crate::event::snapshot::Fmt::to_snapshot(&event);
                let out = format!("{event:?}");
                self.output.push(out);
            }
        }
        fn quic_version(&self) -> u32 {
            1
        }
        fn subject(&self) -> api::Subject {
            builder::Subject::Connection { id: 0 }.into_event()
        }
    }
    impl Drop for Publisher {
        fn drop(&mut self) {
            if std::thread::panicking() {
                return;
            }
            if let Some(location) = self.location.as_ref() {
                location.snapshot_log(&self.output);
            }
        }
    }
}
