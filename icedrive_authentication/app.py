"""Authentication service application."""

import logging
import sys
from typing import List
import time

import Ice
import IceStorm
import IceDrive

from .authentication import Authentication, AuthenticationI
from .discovery import Discovery
from .delayed_response import AuthenticationQuery

class AuthenticationApp(Ice.Application):
    """Implementation of the Ice.Application for the Authentication service."""
    logging.basicConfig(level=logging.INFO)

    def run(self, args: List[str]) -> int:
        """Execute the code for the AuthentacionApp class."""
        adapter = self.communicator().createObjectAdapter("AuthenticationAdapter")
        adapter.activate()

        discovery_topic = self.getTopic("Discovery.Topic")
        auth_query_topic = self.getTopic("Authentication.DeferredResolution.Topic")

        if discovery_topic == -1 or auth_query_topic == -1:
            return -1

        discovery_instance = IceDrive.DiscoveryPrx.checkedCast(adapter.addWithUUID(Discovery())) #escucha
        query_pub = IceDrive.DiscoveryPrx.uncheckedCast(discovery_topic.getPublisher())

        local_servant = Authentication()
        query_pub_amd = IceDrive.AuthenticationQueryPrx.uncheckedCast(auth_query_topic.getPublisher())
        query_receiver_proxy = IceDrive.AuthenticationQueryPrx.checkedCast(adapter.addWithUUID(AuthenticationQuery(local_servant))) #escucha

        servant = AuthenticationI(local_servant, query_pub_amd)
        servant_proxy = IceDrive.AuthenticationPrx.checkedCast(adapter.addWithUUID(servant))

        try:
            discovery_topic.subscribeAndGetPublisher({}, discovery_instance)
            auth_query_topic.subscribeAndGetPublisher({}, query_receiver_proxy)
        except IceStorm.AlreadySubscribed:
            pass

        logging.info("Proxy: %s", servant_proxy)

        self.shutdownOnInterrupt()

        while not self.communicator().isShutdown():
            query_pub.announceAuthentication(servant_proxy)
            try:
                time.sleep(5)
            except KeyboardInterrupt:
                self.communicator().shutdown()

        self.communicator().waitForShutdown()

        return 0

    def getTopic(self, property_name: str):
        """Get a topic from the IceStorm server."""
        properties = self.communicator().getProperties()
        topic_name = properties.getProperty(property_name)
        topic_manager = IceStorm.TopicManagerPrx.checkedCast(self.communicator().propertyToProxy("IceStorm.Proxy"))

        if topic_manager is None:
            return -1

        try:
            topic = topic_manager.retrieve(topic_name)
        except IceStorm.NoSuchTopic:
            topic = topic_manager.create(topic_name)

        return topic

def main():
    """Handle the icedrive-authentication program."""
    app = AuthenticationApp()
    return app.main(sys.argv)

if __name__ == "__main__":
    main()
