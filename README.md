# fair-exchange
Implementation and analysis of a synchronisation protocol for fair exchange with strong fairness and privacy.

I have tested the protocol in the following environment:

Computer:   MacOS version 14.4.1

Python:  what version 3.11

To run the fair exchange protocol to help Alice and Bob to exchange their documents (DA and DB, respectively), execute the following steps:

1. Download the Python code (fairExchange) by selecting 'CODE' and then click on 'DOWNLOAD ZIP' to save it to your machine;
2. Open a terminal and run the main class:  python main.py;
3. From the menu choose option '1', to encrypt Alice’s and Bob’s documents;
4. Deposit operation: after encrypting the documents, select option '2' to execute the deposit operation: Alice’s document is deposited with Bob’s attestable and Bob’s document is deposited with Alice’s attestable;
5. Synchronise operation: select option ‘3’ to execute the synchronisation operation;
6. Select the synchronization type. Use synchronization with the PBB, option '1'.<br>
    <p>a. The result of the exchange will be presented at the end of the synchronization as either 'Success' or 'Cancel'.
    <p>b. As it stands, when executing the synchronise operation, the result will be a success.
7. To run the protocol to produce different outcomes like cancel, for example, because Alice posts Cancel_A and Bob posts Sync_B find the class “SynchronizationProcessService” in the method def pbb_synchronization(self):, choose the case that you want to execute by removing "#". Leave the other cases commented out:
         pbbService.syncA_syncB()
   
        #pbbService.syncA_cancelA_SyncB()
        #pbbService.syncA_cancelB()
        #pbbService.cancelA_syncB()

        #############################
        # pbbService.syncB_syncA()
        # pbbService.syncB_cancelB_SyncA()
        # pbbService.syncB_cancelA()
        # pbbService.cancelB_syncA()

