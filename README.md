# fair-exchange
Implementation and analysis of a synchronisation protocol for fair exchange with strong fairness and privacy.

how to run the script:

1. On the Git, download the script (fairExchange) by selecting 'CODE' and then click on 'DOWNLOAD ZIP' to save it to your machine.
2. Use the terminal to call the main class "main.py";
3. When running, choose option '1', which is to encrypt the document;
4. After the document is encrypted, select option '2' to exchange the document;
5. Once the exchange is executed, the next step is to run the synchronization, in this case, choose option '3';
6. The next step is the synchronization type. For this task, we use synchronization with the PBB, option '1'.
    a. The result of the exchange will be presented at the end of the synchronization as either 'success' or 'failure'.
    b. As it stands, when executing the final step, which is synchronization, the result will be a success.
7. To test other cases and get results like failure (e.g., Cancel_A and Sync_B, or any other case of the 8 explored in the paper), the user should go to the class “SynchronizationProcessService” and in the method def pbb_synchronization(self):, choose the case they want to execute (to do this, remove "#" from the case you want to run and leave the others commented out):
         pbbService.syncA_syncB()
   
        #pbbService.syncA_cancelA_SyncB()
        #pbbService.syncA_cancelB()
        #pbbService.cancelA_syncB()

        #############################
        # pbbService.syncB_syncA()
        # pbbService.syncB_cancelB_SyncA()
        # pbbService.syncB_cancelA()
        # pbbService.cancelB_syncA()

