from appDhully.alice.Configurations import ConfigsAlice
from appDhully.bob.Configurations import ConfigsBob
from appDhully.service.EncryptationProcessService import EncryptationProcessService
from appDhully.service.ExchangeEncyptedFileService import ExchangeEncryptedFile


def main():

    confBob = ConfigsBob()

    file = confBob.configuration.path_file / 'bobdoc_encrypted.txt'
    client_name = 'GCA'
    ExchangeEncryptedFile().upClienteToSendDocumentEncripted(confBob, client_name, file)

if __name__ == '__main__':
    main()