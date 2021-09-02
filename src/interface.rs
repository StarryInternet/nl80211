use crate::attr::*;
use crate::nl80211traits::ParseNlAttr;
use crate::parse_attr::{parse_macaddr, parse_string, parse_u32, parse_u64};
use crate::socket::Socket;
use crate::station::Station;
use macaddr::MacAddr;
use neli::nlattr::AttrHandle;
use std::fmt;

/// A struct representing a wifi interface
#[derive(Clone, Debug, PartialEq)]
pub struct Interface {
    /// A netlink interface index. This index is used to fetch extra information with nl80211
    pub index: Option<u32>,
    /// Interface essid
    pub ssid: Option<String>,
    /// Interface MAC address
    pub mac: Option<MacAddr>,
    /// Interface name
    pub name: Option<String>,
    /// Interface frequency of the selected channel (MHz)
    pub frequency: Option<u32>,
    /// Interface chanel
    pub channel: Option<u32>,
    /// Interface transmit power level in signed mBm units.
    pub power: Option<u32>,
    /// index of wiphy to operate on, cf. /sys/class/ieee80211/<phyname>/index
    pub phy: Option<u32>,
    /// Wireless device identifier, used for pseudo-devices that don't have a netdev
    pub device: Option<u64>,
}

impl Interface {
    pub fn default() -> Interface {
        Interface {
            index: None,
            ssid: None,
            mac: None,
            name: None,
            frequency: None,
            channel: None,
            power: None,
            phy: None,
            device: None,
        }
    }

    /// Get station info for this interface
    pub fn get_station_info(&self) -> Result<Station, neli::err::NlError> {
        if let Some(index) = self.index {
            Socket::connect()?.get_station_info(index)
        } else {
            Err(neli::err::NlError::new("Invalid interface index {:?}"))
        }
    }
}

impl ParseNlAttr for Interface {
    /// Parse netlink messages returned by the nl80211 command CmdGetInterface
    fn parse(&mut self, handle: AttrHandle<Nl80211Attr>) -> Interface {
        for attr in handle.iter() {
            match attr.nla_type {
                Nl80211Attr::AttrIfindex => {
                    self.index = Some(parse_u32(&attr.payload));
                }
                Nl80211Attr::AttrSsid => {
                    self.ssid = Some(parse_string(&attr.payload));
                }
                Nl80211Attr::AttrMac => {
                    self.mac = Some(parse_macaddr(&attr.payload));
                }
                Nl80211Attr::AttrIfname => {
                    self.name = Some(parse_string(&attr.payload));
                }
                Nl80211Attr::AttrWiphyFreq => self.frequency = Some(parse_u32(&attr.payload)),
                Nl80211Attr::AttrChannelWidth => self.channel = Some(parse_u32(&attr.payload)),
                Nl80211Attr::AttrWiphyTxPowerLevel => self.power = Some(parse_u32(&attr.payload)),
                Nl80211Attr::AttrWiphy => self.phy = Some(parse_u32(&attr.payload)),
                Nl80211Attr::AttrWdev => self.device = Some(parse_u64(&attr.payload)),
                _ => (),
            }
        }
        self.to_owned()
    }
}

impl fmt::Display for Interface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut result = Vec::new();

        if let Some(ssid) = &self.ssid {
            result.push(format!("essid : {}", ssid))
        };

        if let Some(mac) = &self.mac {
            result.push(format!("mac : {}", mac))
        };

        if let Some(name) = &self.name {
            result.push(format!("interface : {}", name))
        };

        if let Some(frequency) = self.frequency {
            result.push(format!("frequency : {} Ghz", frequency as f64 / 1000.00))
        };

        if let Some(chanel) = &self.channel {
            result.push(format!("channel : {}", chanel))
        };

        if let Some(power) = &self.power {
            result.push(format!("power : {} dBm", power / 100))
        };

        if let Some(phy) = &self.phy {
            result.push(format!("phy : {}", phy))
        };

        if let Some(device) = &self.device {
            result.push(format!("device : {}", device))
        };

        write!(f, "{}", result.join("\n"))
    }
}

#[cfg(test)]
mod test_interface {
    use super::*;
    use crate::attr::Nl80211Attr::*;
    use neli::nlattr::Nlattr;

    #[test]
    fn test_pretty_format() {
        let interface = Interface {
            index: Some(3),
            ssid: Some("eduroam".into()),
            mac: Some(MacAddr::from([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])),
            name: Some("wlp5s0".into()),
            frequency: Some(2412),
            channel: Some(1),
            power: Some(1700),
            phy: Some(0),
            device: Some(1),
        };

        let expected_output = r#"essid : eduroam
        mac : FF:FF:FF:FF:FF:FF
        interface : wlp5s0
        frequency : 2.412 Ghz
        channel : 1
        power : 17 dBm
        phy : 0
        device : 1"#;

        assert_eq!(
            format!("{}", interface),
            expected_output.replace("\n        ", "\n")
        )
    }

    #[test]
    fn test_parser() {
        let handler = vec![
            Nlattr {
                nla_len: 8,
                nla_type: AttrIfindex,
                payload: vec![3, 0, 0, 0],
            },
            Nlattr {
                nla_len: 11,
                nla_type: AttrIfname,
                payload: vec![119, 108, 112, 53, 115, 48],
            },
            Nlattr {
                nla_len: 8,
                nla_type: AttrWiphy,
                payload: vec![0, 0, 0, 0],
            },
            Nlattr {
                nla_len: 8,
                nla_type: AttrIftype,
                payload: vec![2, 0, 0, 0],
            },
            Nlattr {
                nla_len: 12,
                nla_type: AttrWdev,
                payload: vec![1, 0, 0, 0, 0, 0, 0, 0],
            },
            Nlattr {
                nla_len: 10,
                nla_type: AttrMac,
                payload: vec![255, 255, 255, 255, 255, 255],
            },
            Nlattr {
                nla_len: 8,
                nla_type: AttrGeneration,
                payload: vec![5, 0, 0, 0],
            },
            Nlattr {
                nla_len: 5,
                nla_type: Attr4addr,
                payload: vec![0],
            },
            Nlattr {
                nla_len: 8,
                nla_type: AttrWiphyFreq,
                payload: vec![108, 9, 0, 0],
            },
            Nlattr {
                nla_len: 8,
                nla_type: AttrWiphyChannelType,
                payload: vec![1, 0, 0, 0],
            },
            Nlattr {
                nla_len: 8,
                nla_type: AttrChannelWidth,
                payload: vec![1, 0, 0, 0],
            },
            Nlattr {
                nla_len: 8,
                nla_type: AttrCenterFreq1,
                payload: vec![108, 9, 0, 0],
            },
            Nlattr {
                nla_len: 8,
                nla_type: AttrWiphyTxPowerLevel,
                payload: vec![164, 6, 0, 0],
            },
            Nlattr {
                nla_len: 12,
                nla_type: AttrSsid,
                payload: vec![101, 100, 117, 114, 111, 97, 109],
            },
        ];

        let interface = Interface::default().parse(neli::nlattr::AttrHandle::Owned(handler));

        let expected_interface = Interface {
            index: Some(3),
            ssid: Some("eduroam".into()),
            mac: Some(MacAddr::from([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])),
            name: Some("wlp5s0".into()),
            frequency: Some(2412),
            channel: Some(1),
            power: Some(1700),
            phy: Some(0),
            device: Some(1),
        };

        assert_eq!(interface, expected_interface)
    }
}
