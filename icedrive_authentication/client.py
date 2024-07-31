"""Authentication service application."""

import sys
import Ice
import IceDrive


class AuthenticationClient(Ice.Application):
    """Implementation of the Ice.Application for the Authentication client."""
    def run(self, args):

        if len(args) != 2:
            print("Error: Format is client.py 'proxy'")
            return 1

        proxy = self.communicator().stringToProxy(args[1])
        auth_service = IceDrive.AuthenticationPrx.uncheckedCast(proxy)

        if not auth_service:
            print("El proxy no es correcto")
            return -1

        self.usr_proxies = {}

        print("¿Qué operación quieres realizar?")
        while True:
            try:
                user_input = int(input("\n1. Login (Autenticar)\n2. Crear usuario nuevo\n3. Eliminar usuario\n4. Verificar usuario\n5. Get username\n6. is Alive\n7. Refresh\n8. Salir\n"))

                if user_input == 1:
                    usr = input("\nNombre de usuario: ")
                    pssw = input("Contraseña: ")
                    exisiting_user = auth_service.login(usr, pssw)

                    self.usr_proxies[usr] = exisiting_user
                    print(f"Autenticación correcta. ¡Bienvenid@ de nuevo {exisiting_user.getUsername()}!")

                elif user_input == 2:
                    usr = input("\nNombre de usuario: ")
                    pssw = input("Contraseña: ")
                    new_user = auth_service.newUser(usr, pssw)

                    self.usr_proxies[usr] = new_user
                    print(f"Usuario creado correctamente. ¡Bienvenid@ {new_user.getUsername()}!")

                elif user_input == 3:
                    usr = input("\nNombre de usuario: ")
                    pssw = input("Contraseña: ")

                    auth_service.removeUser(usr, pssw)
                    try:
                        del self.usr_proxies[usr]
                        print("Usuario eliminado correctamente")
                    except KeyError as exc:
                        raise IceDrive.UserNotExist from exc

                elif user_input == 4:
                    usr = input("\nNombre de usuario: ")

                    if usr in self.usr_proxies.keys():
                        usr_object = self.usr_proxies[usr]
                        result = auth_service.verifyUser(usr_object)

                        if result:
                            print("Usuario verificado")
                        else:
                            print("Usuario no verificado en el sistema")
                    else:
                        raise IceDrive.UserNotExist

                elif user_input == 5:
                    usr = input("\nNombre de usuario: ")

                    if usr in self.usr_proxies.keys():
                        username = self.usr_proxies[usr].getUsername()
                        print(f"\nTu nombre de usuario es {username}")
                    else:
                        raise IceDrive.UserNotExist

                elif user_input == 6:
                    usr = input("\nNombre de usuario: ")

                    if usr in self.usr_proxies.keys():
                        alive = self.usr_proxies[usr].isAlive()
                        print(f"Is alive? {alive}")
                    else:
                        raise IceDrive.UserNotExist

                elif user_input == 7:
                    usr = input("\nNombre de usuario: ")

                    if usr in self.usr_proxies.keys():
                        self.usr_proxies[usr].refresh()
                        print("¡Refresh hecho!")
                    else:
                        raise IceDrive.UserNotExist

                elif user_input == 8:
                    return -1

                else:
                    print("El valor introducido debe estar en el rango [1, 8]\n")

            except IceDrive.Unauthorized:
                print("Unauthorized")
                return -1
            except IceDrive.UserAlreadyExists:
                print("User already exists")
                return -1
            except IceDrive.UserNotExist:
                print("User does not exist")
                return -1
            except ValueError:
                print("El valor introducido debe ser numérico\n")

def main():
    """Handle the icedrive-authentication program."""
    app = AuthenticationClient()
    return app.main(sys.argv)

if __name__ == '__main__':
    main()
