from appDhully.alice.Configurations import ConfigsAlice
from appDhully.service.EncryptationProcessService import EncryptationProcessService
from appDhully.service.ExchangeEncyptedFileService import ExchangeEncryptedFile


def main():

    confAlice = ConfigsAlice()
    file = confAlice.configuration.path_file / 'alicedoc_encrypted.txt'
    ExchangeEncryptedFile().upServerToReceivDocEncrypted(confAlice, file)
if __name__ == '__main__':
    main()