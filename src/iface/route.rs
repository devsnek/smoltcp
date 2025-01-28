use crate::time::Instant;
use crate::treebitmap::IpLookupTable;
use crate::wire::{IpAddress, IpCidr};
#[cfg(feature = "proto-ipv4")]
use crate::wire::{Ipv4Address, Ipv4Cidr};
#[cfg(feature = "proto-ipv6")]
use crate::wire::{Ipv6Address, Ipv6Cidr};
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RouteTableFull;

impl core::fmt::Display for RouteTableFull {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Route table full")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RouteTableFull {}

/// A prefix of addresses that should be routed via a router
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Route {
    pub cidr: IpCidr,
    pub via_router: IpAddress,
    /// `None` means "forever".
    pub preferred_until: Option<Instant>,
    /// `None` means "forever".
    pub expires_at: Option<Instant>,
}

#[cfg(feature = "proto-ipv4")]
const IPV4_DEFAULT: IpCidr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address::new(0, 0, 0, 0), 0));
#[cfg(feature = "proto-ipv6")]
const IPV6_DEFAULT: IpCidr =
    IpCidr::Ipv6(Ipv6Cidr::new(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 0), 0));

impl Route {
    /// Returns a route to 0.0.0.0/0 via the `gateway`, with no expiry.
    #[cfg(feature = "proto-ipv4")]
    pub fn new_ipv4_gateway(gateway: Ipv4Address) -> Route {
        Route {
            cidr: IPV4_DEFAULT,
            via_router: gateway.into(),
            preferred_until: None,
            expires_at: None,
        }
    }

    /// Returns a route to ::/0 via the `gateway`, with no expiry.
    #[cfg(feature = "proto-ipv6")]
    pub fn new_ipv6_gateway(gateway: Ipv6Address) -> Route {
        Route {
            cidr: IPV6_DEFAULT,
            via_router: gateway.into(),
            preferred_until: None,
            expires_at: None,
        }
    }
}

/// A routing table.
pub struct Routes {
    v4: IpLookupTable<Ipv4Address, Route>,
    v6: IpLookupTable<Ipv6Address, Route>,
}

impl core::fmt::Debug for Routes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Routes {{ .. }}")
    }
}

impl Routes {
    /// Creates a new empty routing table.
    pub fn new() -> Self {
        Self {
            v4: IpLookupTable::new(),
            v6: IpLookupTable::new(),
        }
    }

    pub fn v4(&self) -> &IpLookupTable<Ipv4Address, Route> {
        &self.v4
    }

    pub fn v4_mut(&mut self) -> &mut IpLookupTable<Ipv4Address, Route> {
        &mut self.v4
    }

    pub fn v6(&self) -> &IpLookupTable<Ipv6Address, Route> {
        &self.v6
    }

    pub fn v6_mut(&mut self) -> &mut IpLookupTable<Ipv6Address, Route> {
        &mut self.v6
    }

    /// Add a default ipv4 gateway (ie. "ip route add 0.0.0.0/0 via `gateway`").
    ///
    /// On success, returns the previous default route, if any.
    #[cfg(feature = "proto-ipv4")]
    pub fn add_default_ipv4_route(
        &mut self,
        gateway: Ipv4Address,
    ) -> Result<Option<Route>, RouteTableFull> {
        let old = self.remove_default_ipv4_route();
        self.v4
            .insert([0; 4].into(), 0, Route::new_ipv4_gateway(gateway));
        Ok(old)
    }

    /// Add a default ipv6 gateway (ie. "ip -6 route add ::/0 via `gateway`").
    ///
    /// On success, returns the previous default route, if any.
    #[cfg(feature = "proto-ipv6")]
    pub fn add_default_ipv6_route(
        &mut self,
        gateway: Ipv6Address,
    ) -> Result<Option<Route>, RouteTableFull> {
        let old = self.remove_default_ipv6_route();
        self.v6
            .insert([0; 8].into(), 0, Route::new_ipv6_gateway(gateway));
        Ok(old)
    }

    /// Remove the default ipv4 gateway
    ///
    /// On success, returns the previous default route, if any.
    #[cfg(feature = "proto-ipv4")]
    pub fn remove_default_ipv4_route(&mut self) -> Option<Route> {
        self.v4.remove([0; 4].into(), 0)
    }

    /// Remove the default ipv6 gateway
    ///
    /// On success, returns the previous default route, if any.
    #[cfg(feature = "proto-ipv6")]
    pub fn remove_default_ipv6_route(&mut self) -> Option<Route> {
        self.v6.remove([0; 8].into(), 0)
    }

    pub(crate) fn lookup(&self, addr: &IpAddress, timestamp: Instant) -> Option<IpAddress> {
        assert!(addr.is_unicast());

        loop {
            let route = match addr {
                IpAddress::Ipv4(addr) => self.v4.longest_match(*addr)?.2,
                IpAddress::Ipv6(addr) => self.v6.longest_match(*addr)?.2,
            };

            /*
            if let Some(expires_at) = route.expires_at {
                if timestamp > expires_at {
                    match route.cidr.address() {
                        IpAddress::Ipv4(addr) => {
                            self.v4.remove(addr, route.cidr.prefix_len() as _);
                        }
                        IpAddress::Ipv6(addr) => {
                            self.v6.remove(addr, route.cidr.prefix_len() as _);
                        }
                    }
                    continue;
                }
            }
            */

            break Some(route.via_router);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[cfg(feature = "proto-ipv6")]
    mod mock {
        use super::super::*;
        pub const ADDR_1A: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 2, 0, 0, 0, 1);
        pub const ADDR_1B: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 2, 0, 0, 0, 13);
        pub const ADDR_1C: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 2, 0, 0, 0, 42);
        pub fn cidr_1() -> Ipv6Cidr {
            Ipv6Cidr::new(Ipv6Address::new(0xfe80, 0, 0, 2, 0, 0, 0, 0), 64)
        }

        pub const ADDR_2A: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0x3364, 0, 0, 0, 1);
        pub const ADDR_2B: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0x3364, 0, 0, 0, 21);
        pub fn cidr_2() -> Ipv6Cidr {
            Ipv6Cidr::new(Ipv6Address::new(0xfe80, 0, 0, 0x3364, 0, 0, 0, 0), 64)
        }
    }

    #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
    mod mock {
        use super::super::*;
        pub const ADDR_1A: Ipv4Address = Ipv4Address::new(192, 0, 2, 1);
        pub const ADDR_1B: Ipv4Address = Ipv4Address::new(192, 0, 2, 13);
        pub const ADDR_1C: Ipv4Address = Ipv4Address::new(192, 0, 2, 42);
        pub fn cidr_1() -> Ipv4Cidr {
            Ipv4Cidr::new(Ipv4Address::new(192, 0, 2, 0), 24)
        }

        pub const ADDR_2A: Ipv4Address = Ipv4Address::new(198, 51, 100, 1);
        pub const ADDR_2B: Ipv4Address = Ipv4Address::new(198, 51, 100, 21);
        pub fn cidr_2() -> Ipv4Cidr {
            Ipv4Cidr::new(Ipv4Address::new(198, 51, 100, 0), 24)
        }
    }

    use self::mock::*;

    #[test]
    fn test_fill() {
        let mut routes = Routes::new();

        assert_eq!(
            routes.lookup(&ADDR_1A.into(), Instant::from_millis(0)),
            None
        );
        assert_eq!(
            routes.lookup(&ADDR_1B.into(), Instant::from_millis(0)),
            None
        );
        assert_eq!(
            routes.lookup(&ADDR_1C.into(), Instant::from_millis(0)),
            None
        );
        assert_eq!(
            routes.lookup(&ADDR_2A.into(), Instant::from_millis(0)),
            None
        );
        assert_eq!(
            routes.lookup(&ADDR_2B.into(), Instant::from_millis(0)),
            None
        );

        let route = Route {
            cidr: cidr_1().into(),
            via_router: ADDR_1A.into(),
            preferred_until: None,
            expires_at: None,
        };
        routes.update(|storage| {
            storage.push(route);
        });

        assert_eq!(
            routes.lookup(&ADDR_1A.into(), Instant::from_millis(0)),
            Some(ADDR_1A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_1B.into(), Instant::from_millis(0)),
            Some(ADDR_1A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_1C.into(), Instant::from_millis(0)),
            Some(ADDR_1A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_2A.into(), Instant::from_millis(0)),
            None
        );
        assert_eq!(
            routes.lookup(&ADDR_2B.into(), Instant::from_millis(0)),
            None
        );

        let route2 = Route {
            cidr: cidr_2().into(),
            via_router: ADDR_2A.into(),
            preferred_until: Some(Instant::from_millis(10)),
            expires_at: Some(Instant::from_millis(10)),
        };
        routes.update(|storage| {
            storage.push(route2).unwrap();
        });

        assert_eq!(
            routes.lookup(&ADDR_1A.into(), Instant::from_millis(0)),
            Some(ADDR_1A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_1B.into(), Instant::from_millis(0)),
            Some(ADDR_1A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_1C.into(), Instant::from_millis(0)),
            Some(ADDR_1A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_2A.into(), Instant::from_millis(0)),
            Some(ADDR_2A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_2B.into(), Instant::from_millis(0)),
            Some(ADDR_2A.into())
        );

        assert_eq!(
            routes.lookup(&ADDR_1A.into(), Instant::from_millis(10)),
            Some(ADDR_1A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_1B.into(), Instant::from_millis(10)),
            Some(ADDR_1A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_1C.into(), Instant::from_millis(10)),
            Some(ADDR_1A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_2A.into(), Instant::from_millis(10)),
            Some(ADDR_2A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_2B.into(), Instant::from_millis(10)),
            Some(ADDR_2A.into())
        );
    }
}
