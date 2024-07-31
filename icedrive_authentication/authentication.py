"""Module for servants implementations."""

import json
import threading
import logging
import sys
import Ice
import IceDrive
from .delayed_response import AuthenticationQueryResponse, AuthenticationQuery

class User(IceDrive.User):
    """Implementation of an IceDrive.User interface."""

    def __init__(self, usr: str, passw: str):
        self.username = usr
        self.password = passw
        self.expiration_time = threading.Timer(120.0, self.callback)
        self.expiration_time.start()

    def getUsername(self, current: Ice.Current = None) -> str:
        """Return the username for the User object."""
        logging.info("[getUsername] Nombre de usuario: %s", self.username)
        return self.username

    def isAlive(self, current: Ice.Current = None) -> bool:
        """Check if the authentication is still valid or not."""
        logging.info("¿Está vivo? %s", self.expiration_time.is_alive())
        return self.expiration_time.is_alive()

    def refresh(self, current: Ice.Current = None) -> None:
        """Renew the authentication for 1 more period of time."""
        if self.expiration_time.is_alive():
            self.expiration_time = threading.Timer(120.0, self.callback)
            self.expiration_time.start()
            logging.info("Refresh hecho")
        else:
            logging.info("El usuario ha expirado")
            raise IceDrive.Unauthorized(self.username)
    #raise UserNotExist

    def callback(self):
        """Function called when the timer has expired"""
        logging.info("Usuario expirado")
        del self

class AuthenticationI(IceDrive.Authentication):
    """Implementation of an IceDrive.Authentication interface that handles asynchronous queries."""
    def __init__(self, authentication: 'Authentication', query_publisher : AuthenticationQuery):
        """Constructor of the authenticator"""
        self.auth = authentication
        self.query_pub = query_publisher
        self.expected_responses = {}

    def callback(self, adapter: Ice.ObjectAdapter, identity: Ice.Identity) -> None:
        """Remove an object from the adapter if exists"""
        if adapter.find(identity) is not None:
            adapter.remove(identity)

        del self.expected_responses[identity]

    def amdResponse(self, current: Ice.Current = None) -> IceDrive.AuthenticationQueryResponsePrx:
        """Prepare an Ice.Future object"""
        future = Ice.Future()
        response = AuthenticationQueryResponse(future)
        prx = current.adapter.addWithUUID(response)
        query_response_proxy = IceDrive.AuthenticationQueryResponsePrx.uncheckedCast(prx)

        identity = query_response_proxy.ice_getIdentity()
        self.expected_responses[identity] = future
        timer = threading.Timer(5.0, self.callback, (current.adapter, identity))
        timer.start()

        return query_response_proxy

    def login(self, username: str, password: str, current: Ice.Current = None) -> IceDrive.UserPrx:
        """Authenticate an user by username and password and return its User."""
        try:
            logging.info("Intentando login síncrono")
            return self.auth.login(username, password, current)
        except IceDrive.Unauthorized:
            try:
                logging.info("Iniciando consulta asinc login")
                response_prx = self.amdResponse(current)
                self.query_pub.login(username, password, response_prx)
                response = self.expected_responses[response_prx.ice_getIdentity()]
                return response.result(5)
            except (IceDrive.Unauthorized, Ice.TimeoutException) as e:
                try:
                    logging.info(" TO: No existe el usuario")
                    raise IceDrive.Unauthorized(username) from e
                except Ice.TimeoutException:
                    raise IceDrive.Unauthorized(username) from e

    def newUser(self, username: str, password: str, current: Ice.Current=None) -> IceDrive.UserPrx:
        """Create an user with username and the given password."""
        logging.info("Comprobando asinc newUser")
        response_prx = self.amdResponse(current)
        self.query_pub.doesUserExists(username, response_prx)
        response = self.expected_responses[response_prx.ice_getIdentity()]
        try:
            if response.result(5) == username:
                current.adapter.remove(response_prx.ice_getIdentity())
                raise IceDrive.UserAlreadyExists(username)
        except Ice.TimeoutException:
            if current.adapter.find(response_prx.ice_getIdentity()) is not None:
                current.adapter.remove(response_prx.ice_getIdentity())

            logging.info("No existe el usuario, comprobando en local...")
            return self.auth.newUser(username, password, current)

    def removeUser(self, username: str, password: str, current: Ice.Current = None) -> None:
        """Remove the user "username" if the "password" is correct."""
        try:
            logging.info("Intentando remove síncrono")
            self.auth.removeUser(username,password, current)
        except IceDrive.Unauthorized:
            try:
                logging.info("Iniciando consulta asinc remove")
                response_prx = self.amdResponse(current)
                self.query_pub.removeUser(username, password, response_prx)

                response = self.expected_responses[response_prx.ice_getIdentity()]
                if response.result(5) is None:
                    current.adapter.remove(response_prx.ice_getIdentity())

            except (IceDrive.Unauthorized, Ice.TimeoutException) as e:
                try:
                    logging.info(" TO: No existe el usuario")
                    raise IceDrive.Unauthorized(username) from e
                except Ice.TimeoutException:
                    raise IceDrive.Unauthorized(username) from e

    def verifyUser(self, user: IceDrive.UserPrx, current: Ice.Current = None) -> bool:
        """Check if the user belongs to this service."""
        try:
            logging.info("Intentando verify síncrono")
            return self.auth.verifyUser(user, current)
        except IceDrive.Unauthorized:
            logging.info("Iniciando consulta asinc verify")
            response_prx = self.amdResponse(current)
            self.query_pub.verifyUser(user, response_prx)
            try:
                b = self.expected_responses[response_prx.ice_getIdentity()].result(5)
                current.adapter.remove(response_prx.ice_getIdentity())
                if b:
                    logging.info(" RM: Usuario verificado")
                    return True
                logging.info(" TO: Usuario no verificado")
                return False
            except (IceDrive.Unauthorized, Ice.TimeoutException):
                try:
                    logging.info(" TO: Usuario no verificado")
                    return False
                except Ice.TimeoutException:
                    return False

class Authentication(IceDrive.Authentication):
    """Implementation of an IceDrive.Authentication interface."""

    def __init__(self):
        """Constructor of the authenticator"""
        self.usersprx = {}
        self.users = {}

    def readFile(self, current: Ice.Current = None):
        """Function to read the json file"""
        try:
            with open('user_credentials.json', 'r', encoding='utf-8') as file:
                self.users = json.load(file)
                if not self.users: #si el json está vacío
                    self.users = {}
                else:
                    for usrname, pssw in self.users.items():
                        user = User(usrname, pssw)
                        current.adapter.addWithUUID(user)
        except FileNotFoundError:
            logging.info("No json file, creating...")
            self.users = {}
            with open('user_credentials.json', 'w', encoding='utf-8') as f:
                json.dump(self.users, f)
        except json.JSONDecodeError:
            logging.info("Error in the format of the json file")
            self.users = {}
            with open('user_credentials.json', 'w', encoding='utf-8') as f:
                json.dump(self.users, f)

    def updateFile(self):
        """Function to update the json file"""
        try:
            with open('user_credentials.json', 'w', encoding='utf-8') as json_file:
                json.dump(self.users, json_file)
        except json.JSONDecodeError:
            logging.info("Error in the format of the json file")
            sys.exit(1)

    logging.basicConfig(level=logging.INFO)

    def findUser(self, username: str, current: Ice.Current = None) -> bool:
        """Return the User object for the given username."""

        self.readFile(current)

        if username in self.users.keys():
            logging.info("[FindUser] El usuario existe")
            return True
        logging.info("[FindUser] El usuario no existe")
        return False

    def login(self, username: str, password: str, current: Ice.Current) -> IceDrive.UserPrx:
        """Authenticate an user by username and password and return its User."""
        self.readFile(current)
        if username in self.users.keys():
            if self.users[username] == password:
                try:
                    existing_prx = self.usersprx[username]
                    existing_usr = IceDrive.UserPrx.uncheckedCast(existing_prx)
                    existing_usr.refresh()

                    logging.info("Login hecho")
                    return existing_usr
                except KeyError as e:
                    logging.info("El proxy no existe aunque el usuario está en la persistencia")
                    raise IceDrive.Unauthorized(username) from e

            else:
                logging.info("Contraseña incorrecta")
                raise IceDrive.Unauthorized(username)
        logging.info("El usuario no está en la persistencia")
        raise IceDrive.Unauthorized(username)

    def newUser(self, username: str, password: str, current: Ice.Current=None) -> IceDrive.UserPrx:
        """Create an user with username and the given password."""
        self.readFile(current)

        if username in self.users:
            logging.info("El usuario ya existe")
            raise IceDrive.UserAlreadyExists(username)

        new_user = User(username, password)
        self.users[username] = password
        usr_prx = IceDrive.UserPrx.uncheckedCast(current.adapter.addWithUUID(new_user))
        self.usersprx[username] = usr_prx

        logging.info("Usuario creado")
        self.updateFile()
        return usr_prx

    def removeUser(self, username: str, password: str, current: Ice.Current = None) -> None:
        """Remove the user "username" if the "password" is correct."""
        self.readFile(current)

        if username in self.users.keys():
            if self.users[username] == password:

                try:
                    user_proxy = self.usersprx[username]
                    rm_user = current.adapter.findByProxy(user_proxy)
                    rm_user.expiration_time.cancel()
                    del rm_user
                    del self.users[username]
                    current.adapter.remove(user_proxy.ice_getIdentity())
                    logging.info("Usuario eliminado")
                    del self.usersprx[username]
                    self.updateFile()
                except KeyError:
                    logging.info("El proxy no existe aunque el usuario está en la persistencia")

            else:
                logging.info("Contraseña incorrecta")
                raise IceDrive.Unauthorized(username)
        else:
            logging.info("El usuario no existe")
            raise IceDrive.Unauthorized(username)

    def verifyUser(self, user: IceDrive.UserPrx, current: Ice.Current = None) -> bool:
        """Check if the user belongs to this service.

        Don't check anything related to its my_authentication state or anything else.
        """
        try:
            if current.adapter.findByProxy(self.usersprx[user.getUsername()]):
                logging.info("Usuario verificado")
                return True
        except (AttributeError, KeyError, TypeError):
            logging.info("Usuario no verificado")
            return False
