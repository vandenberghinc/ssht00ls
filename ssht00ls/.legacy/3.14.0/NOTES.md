
# DEV Notes.

## Create systemd process.
For mac also. Create in package syst3m.

## Create static "deleted" cache.
When 2 folders are synced and then stopped syncing and the local deletes the file & the rsyncing later starts, the deleted file will be created due to dynamic deleted cache. So creaete a seperate "deleted" cache per absolute path & chcek if the deleted time from the cache is later then the remote time, if so delete remote.