import os
from scapy.all import *
import fcntl
from struct import pack, unpack
import yaml
import logging
from webhooks import WebHookType, WebHook
import validators

class AppSettings:
    def __init__(self, daemon=False, settingsfile='tripwire.conf', logfile='tripwire.log'):
        

        self.iface = 'lo'
        self.listening_tcp_ports = []
        self.listening_udp_ports = []
        self.daemon = daemon

        if os.path.exists(settingsfile):
            self.__load_settings(settingsfile)
        else:
            msg = "Valid config file not detected. Using defaults."
            logging.warning(msg)
            self.__set_defaults()


    def __load_settings(self, settingsfile):
        with open(settingsfile, 'r') as stream:
            try:
                settings = yaml.safe_load(stream)

                self.debug = self.__assign_value( settings, "debug", "False")
                self.iface = self.__assign_value( settings, "iface", "lo" )
                self.listening_tcp_ports = self.__assign_value( settings, "tcp_ports", [22] )
                self.listening_udp_ports = self.__assign_value( settings, "udp_ports", [1194] )
                self.ignore_hosts = self.__assign_value( settings, "ignore_hosts", [] )

                self.listening_ip = get_if_addr(self.iface)
                if self.listening_ip:
                    return 
                else:
                    print('No ip found for {self.iface}')

                if 'webhook_url' in settings:
                    url = settings['webhook_url']

                    # If there is a bad URL, just drop webhook support
                    if validators.url(url):
                        self.webhook = url
                        self.webhook_type = self.__assign_value( settings, "webhook_type", WebHookType.GENERIC )
                    else:
                        logging.warning( "Bad webhook URL. Disabling webhook support." )
                        self.webhook = None
                        self.webhook_type = WebHookType.NONE
                else:
                    self.webhook = None
                    self.webhook_type = WebHookType.NONE
            except yaml.YAMLError as exc:
                logging.exception(exc)
                self.__set_defaults()

    def __assign_value(self, settings, key, default_val ):                
        if key in settings:
            val = settings[key]
        else:
            logging.warning( f"'{key}' settings missing from config. Using defaults.")
            val = default_val
        return val

    def __set_defaults(self):
        self.debug = False
        self.iface = 'en0'
        self.listening_ports = [8080]
        self.webhook = None
        self.webhook_type = WebHookType.NONE
