## isolock

**isolock** is a locking manager for **isolate**, available as part of the [MOE contest environment](http://www.ucw.cz/moe/). **isolate** allows you to sandbox programs/processes into a chroot jail, with a unique user id (and group id), thereby limiting what programs can do. It is installed with a limited number of *boxes*, based on the user ids allocated for **isolate** to use. **isolock** is an advisory locking manager, to allocate the desired number of box_ids that are unused.

### Installation

First install **isolate**, then download this git repository, and run **make**. Copy bin/isolock to a desired location, and make sure it is on your path. It is designed to run setuid as root, so `chown` and `chmod` it.

```bash
git clone git://github.com/ronalchn/isolock.git
cd isolock
make
sudo chown root bin/isolock
sudo chmod +s bin/isolock
```

### Usage

Run the help command for all the options:

```bash
isolock --help
```

Essentially, you can request locks for **N** boxes. **isolock** will either print the box_ids for <N> boxes to stdout, or if there are not enough free boxes, and the timeout runs out, return an error. When you are finished, just pass those box_ids back into **isolock** with the `--free` option to release the locks. You can set a timeout using the `--timeout` option, which is normally set to 0, which means wait indefinitely.

The `-n` option, which allows you to request **N** boxes at once is designed to prevent deadlocks. If the required number of boxes could not be locked initially, and the waiting time has not run out, **isolock** will release those locks, then acquire a "master" waiting lock, before again locking any free locks as they become available. Thus, for requests which are not immediately successful, all free resources will be used to fulfill the request with the "master" lock first.

**isolock** locks are owned by a calling process. The lock is valid until freed, or until the calling process terminates (ie. while the PID remains valid). If you wish to transfer the lock from one process to another, you can overwrite the new PID and start_time (in jiffies since boot) in the format "%d:%llu\n" to the lock directory, which by default is `printf("/var/lock/isolate/lock/%d.pidlock", box_id)`.




