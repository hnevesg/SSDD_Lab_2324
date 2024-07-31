"""Servant implementations for service discovery."""

import logging
import Ice
import IceDrive

class Discovery(IceDrive.Discovery):
    """Servants class for service discovery."""

    authentication_services = set()
    directory_services = set()
    blob_services = set()

    def checkProxy(self, proxy) -> int:
        """Check if the proxy is missing."""
        if not proxy:
            logging.info("ERROR: proxy missing!")
            return -1
        return 0

    def announceAuthentication(self, prx: IceDrive.AuthenticationPrx, current: Ice.Current = None) -> None:
        """Receive an Authentication service announcement."""
        if self.checkProxy(prx) != -1:
            auth_prx = IceDrive.AuthenticationQueryPrx.uncheckedCast(prx)
            logging.info("Authentication discovered: %s", auth_prx)

            self.authentication_services.add(prx)

    def announceDirectoryService(self, prx: IceDrive.DirectoryServicePrx, current: Ice.Current = None) -> None:
        """Receive an Directory service announcement."""
        if self.checkProxy(prx) != -1:
            directory_prx = IceDrive.DirectoryQueryPrx.uncheckedCast(prx)
            logging.info("Directory discovered: %s", directory_prx)

            self.directory_services.add(prx)

    def announceBlobService(self, prx: IceDrive.BlobServicePrx, current: Ice.Current = None) -> None:
        """Receive an Blob service announcement."""
        if self.checkProxy(prx) != -1:
            blob_prx = IceDrive.BlobQueryPrx.uncheckedCast(prx)
            logging.info("Blob discovered: %s", blob_prx)

            self.blob_services.add(blob_prx)
