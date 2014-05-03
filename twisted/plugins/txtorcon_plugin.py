#!/usr/bin/env python

from zope.interface import implementer
from twisted.plugin import IPlugin
from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor, defer
from twisted.internet.interfaces import IStreamServerEndpointStringParser, IStreamServerEndpoint
from twisted.internet.endpoints import serverFromString
from twisted.internet.endpoints import TCP4ServerEndpoint

import txtorcon


@implementer(IStreamServerEndpoint)
class LaunchTorEndpoint(object):
    """
    Wants a better name...
    Launches tor then uses underlying TCPHiddenServiceEndpoint to
    create a hidden service. Ultimately the user getting back an IPort
    with .onion and .private_key attributes added.
    """

    def __init__(self, reactor, config, public_port, hs_dir=None, local_port=None):
        self.reactor = reactor
        self.config = config
        self.public_port = public_port

        if local_port is not None:
            self.endpoint = txtorcon.TCPHiddenServiceEndpoint(self.reactor, self.config,
                                                              self.public_port, data_dir=hs_dir,
                                                              port_generator=lambda: local_port)
        else:
            self.endpoint = txtorcon.TCPHiddenServiceEndpoint(self.reactor, self.config,
                                                              self.public_port, data_dir=hs_dir)

    def progress(self, percent, tag, message):
        pass

    @defer.inlineCallbacks
    def listen(self, protocol_factory):
        """IStreamServerEndpoint API"""
        tor_process = yield txtorcon.launch_tor(self.config, self.reactor, progress_updates=self.progress)
        port = yield self.endpoint.listen(protocol_factory)
        port.onion_port = self.public_port
        defer.returnValue(port)


@implementer(IPlugin, IStreamServerEndpointStringParser)
class TorHiddenServiceEndpointStringParser(object):
    prefix = "onion"

    def _parseServer(self, reactor, controlPort=None, publicPort=None, hiddenServiceDir=None, localPort=None):
        assert publicPort is not None

        publicPort = int(publicPort)

        config = txtorcon.TorConfig()
        config.socksPort = 0                                        # no SOCKS listener
        ## FIXME TODO THINK
        ## maybe setting controlPort should mean "I've already got a
        ## Tor running, and wish you to please connect to that"
        ## whereas NOT specifying it means "please launch a new Tor
        ## instance"?
        if controlPort is not None:                                 # ...or let txtorcon pick
            config.ControlPort = int(controlPort)

        ## specify which local port to listen on. in the future, Tor
        ## will support having hidden services listen on unix sockets,
        ## too, so then it would make sense to allow a pathname here
        ## too, probably (e.g. if int(localPort) fails, try path)
        if localPort is not None:
            localPort = int(localPort)

        return LaunchTorEndpoint(reactor, config, publicPort, hiddenServiceDir, localPort)

    def parseStreamServer(self, reactor, *args, **kwargs):
        return self._parseServer(reactor, *args, **kwargs)



torHiddenServiceEndpointStringParser = TorHiddenServiceEndpointStringParser()
