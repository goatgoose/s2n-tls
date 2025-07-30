// TODO: autogenerate from s2n-quic-events. will live in generated.rs.

pub mod ffi {
    use std::any::Any;
    use std::ffi::c_void;
    use s2n_quic_core::event::Event;
    use s2n_quic_core::query;
    use s2n_quic_core::query::{ControlFlow, Query};
    use crate::event::{api, Meta};
    use crate::event::api::{ApplicationProtocolInformation, ConnectionInfo, ConnectionMeta};
    use super::super::event::*;

    pub mod c_bridge {
        use std::any::Any;
        use std::ffi::c_void;
        use std::time::SystemTime;
        use s2n_quic_core::event::IntoEvent;
        use crate::event;
        use crate::event::{api, ConnectionPublisher, ConnectionPublisherSubscriber, Subscriber};
        use crate::event::api::{ApplicationProtocolInformation, ConnectionInfo, ConnectionMeta};

        pub trait ErasedEventSubscriber: 'static + Send + Sync {
            fn create_connection_context_erased(
                &self,
                meta: &ConnectionMeta,
                info: &ConnectionInfo,
            ) -> Box<dyn Any + Send + Sync + 'static>;

            fn on_application_protocol_information_erased(
                &self,
                context: &dyn Any,
                meta: event::builder::ConnectionMeta,
                event: event::builder::ApplicationProtocolInformation,
            ) {
                let _ = context;
                let _ = meta;
                let _ = event;
            }

            // fn on_event_erased<M: Meta, E: Event>(&self, meta: &M, event: &E) {
            //     let _ = meta;
            //     let _ = event;
            // }
            //
            // fn on_connection_event_erased<E: Event>(
            //     &self,
            //     context: &dyn Any,
            //     meta: &api::ConnectionMeta,
            //     event: &E,
            // ) {
            //     let _ = context;
            //     let _ = meta;
            //     let _ = event;
            // }
            //
            // fn query_erased(
            //     context: &dyn Any,
            //     query: &mut dyn query::Query,
            // ) -> query::ControlFlow {
            //     query.execute(context)
            // }
        }

        struct EventSubscriberWrapper<S: Subscriber> {
            pub inner: S,
        }

        pub fn subscriber_to_ptr<S: Subscriber>(subscriber: S) -> *mut c_void {
            // Wrap the subscriber
            let wrapper = EventSubscriberWrapper { inner: subscriber };

            // Box it as a trait object
            let boxed: Box<dyn ErasedEventSubscriber> = Box::new(wrapper);

            // Box the box to get a thin pointer we can store as c_void
            let boxed_box = Box::new(boxed);
            let raw = Box::into_raw(boxed_box) as *mut c_void;
            raw
        }

        impl<S> ErasedEventSubscriber for EventSubscriberWrapper<S>
        where
            S: Subscriber,
        {
            fn create_connection_context_erased(&self, meta: &ConnectionMeta, info: &ConnectionInfo) -> Box<dyn Any + Send + Sync + 'static> {
                Box::new(self.inner.create_connection_context(meta, info))
            }

            fn on_application_protocol_information_erased(&self, context: &dyn Any, meta: event::builder::ConnectionMeta, event: event::builder::ApplicationProtocolInformation) {
                let typed_context = context.downcast_ref::<S::ConnectionContext>().unwrap();
                let publisher = ConnectionPublisherSubscriber::new(
                    meta,
                    1,
                    &self.inner,
                    &typed_context,
                );
                publisher.on_application_protocol_information(event);
            }

            // fn on_event_erased<M: Meta, E: Event>(&self, meta: &M, event: &E) {
            //     self.inner.on_event(meta, event);
            // }
            //
            // fn on_connection_event_erased<E: Event>(&self, context: &dyn Any, meta: &ConnectionMeta, event: &E) {
            //     let typed_context = context.downcast_ref::<S::ConnectionContext>().unwrap();
            //     self.inner.on_connection_event(typed_context, meta, event);
            // }
            //
            // fn query_erased(context: &dyn Any, query: &mut dyn Query) -> ControlFlow {
            //     let typed_context = context.downcast_ref::<S::ConnectionContext>().unwrap();
            //     query.execute(typed_context)
            // }
        }
    }

    pub mod c_api {
        use std::any::Any;
        use std::ffi::{c_int, c_void};
        use std::time::SystemTime;
        use s2n_quic_core::event::{IntoEvent, Timestamp};
        use crate::event::api;
        use super::c_bridge;

        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn subscriber_create_connection_context(
            subscriber: *mut c_void
        ) -> *mut c_void {
            unsafe {
                let subscriber_box = &*(subscriber as *const Box<dyn c_bridge::ErasedEventSubscriber>);
                let subscriber = &**subscriber_box;

                // TODO: create in C and pass in to function
                let meta = api::ConnectionMeta {
                    id: 0,
                    timestamp: s2n_quic_core::time::Timestamp::from_duration(SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap()).into_event(),
                };
                let info = api::ConnectionInfo {};

                let context_box = subscriber.create_connection_context_erased(&meta, &info);
                let context_box_box = Box::new(context_box);
                let context_ptr = Box::into_raw(context_box_box) as *mut c_void;
                context_ptr
            }
        }

        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn subscriber_on_application_protocol_information(
            subscriber: *mut c_void,
            context: *mut c_void,
            alpn: *mut u8,
            alpn_len: u32,
        ) -> c_int {
            unsafe {
                let subscriber_box = &*(subscriber as *const Box<dyn c_bridge::ErasedEventSubscriber>);
                let subscriber = &**subscriber_box;

                let context_box = &*(context as *const Box<dyn Any + Send + Sync>);
                let context = &**context_box;

                // TODO: create in C and pass in to function
                let meta = crate::event::builder::ConnectionMeta {
                    id: 0,
                    timestamp: s2n_quic_core::time::Timestamp::from_duration(SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap()).into_event(),
                };

                let event = crate::event::builder::ApplicationProtocolInformation {
                    chosen_application_protocol: std::slice::from_raw_parts(alpn, alpn_len.try_into().unwrap()),
                };

                subscriber.on_application_protocol_information_erased(context, meta, event);
            }

            0
        }
    }
}
