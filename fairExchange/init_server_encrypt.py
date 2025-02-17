from appDhully.alice.Configurations import ConfigsAlice
from appDhully.service.EncryptationProcessService import EncryptationProcessService


def main():

    confAlice = ConfigsAlice()
    EncryptationProcessService().start_server(confAlice)
if __name__ == '__main__':
    main()