"""Servant implementation for the delayed response mechanism."""

import logging
import Ice
import IceDrive

class AuthenticationQueryResponse(IceDrive.AuthenticationQueryResponse):
    """Query response receiver."""
    def __init__(self, future: Ice.Future) -> None:
        """Initialize a query response handler."""
        self.future_callback = future

    def loginResponse(self, user: IceDrive.UserPrx, current: Ice.Current = None) -> None:
        """Receive an User when other service instance knows about it and credentials are correct."""
        if user is not None:
            self.future_callback.set_result(user)
            logging.info("Response: Usuario correcto")
            current.adapter.remove(current.id)

    def userExists(self, username: str, current: Ice.Current = None) -> None:
        """Receive an invocation when other service instance knows about the user."""
        self.future_callback.set_result(username)
        logging.info("Response: El usuario existe")
        current.adapter.remove(current.id)

    def userRemoved(self, current: Ice.Current = None) -> None:
        """Receive an invocation when other service instance knows the user and removed it."""
        logging.info("Response: Usuario eliminado")
        current.adapter.remove(current.id)

    def verifyUserResponse(self, result: bool, current: Ice.Current = None) -> None:
        """Receive a boolean when other service instance is owner of the user."""
        if result is True:
            self.future_callback.set_result(result)
            logging.info("Response: Usuario verificado")
            current.adapter.remove(current.id)


class AuthenticationQuery(IceDrive.AuthenticationQuery):
    """Query receiver."""
    def __init__(self, authentication):
        """Initialize a AuthenticationQuery receiver."""
        self.authentication = authentication

    def login(self, username: str, password: str, response: IceDrive.AuthenticationQueryResponsePrx, current: Ice.Current = None) -> None:
        """Receive a query about an user login."""
        try:
            logging.info("Login query received")
            answer = self.authentication.login(username, password, current)
            response.loginResponse(answer, current)
        except IceDrive.Unauthorized:
            return

    def doesUserExists(self, username: str, response: IceDrive.AuthenticationQueryResponsePrx, current: Ice.Current = None) -> None:
        """Receive a query about an user existence."""        
        logging.info("UserExists query received")
        if self.authentication.findUser(username, current):
            response.userExists(username)
        else:
            return

    def removeUser(self, username: str, password: str, response: IceDrive.AuthenticationQueryResponsePrx, current: Ice.Current = None) -> None:
        """Receive a query about an user to be removed."""
        try:
            logging.info("RemoveUser query received")
            self.authentication.removeUser(username, password, current)
            response.userRemoved()
        except IceDrive.Unauthorized:
            return

    def verifyUser(self, user: IceDrive.UserPrx, response: IceDrive.AuthenticationQueryResponsePrx, current: Ice.Current = None) -> None:
        """Receive a query about an user to be verified."""
        logging.info("VerifyUser query received")
        answer = self.authentication.verifyUser(user, current)
        response.verifyUserResponse(answer)
