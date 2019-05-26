[![CircleCI](https://circleci.com/gh/JackOfMostTrades/catlog.svg?style=svg)](https://circleci.com/gh/JackOfMostTrades/catlog)

CaTLog
======
_For putting cats in your CTLog_

# Prerequisites
If you are only reading catlog data out of CT logs, there are no prerequisites. You should be able to get by just
running the `catlog clone` and `catlog pull` commands.

If, however, you intend to push data to CT logs with catlog, there are a few of prerequisites. These prerequisites are
necessary in order to satisfy the many domain verification challenges required to mint the publicly-trusted certificates
encoding data that will ultimately live in the CT logs.

* You must own a domain name for which you can set nameserver (NS) records.
* You must been running on an instance with a publicly-routable IP (or at least be capabable of setting up
NAT/port-forwarding rules so that DNS requests (UDP port 53) are routed to your machine.
* You must be running as a user with local privileges sufficient to bind to port 53. You could do this by running as
root (generally discouraged) or by using a tool like authbind.

Assuming these prerequisites are satisfied, follow these steps to get started:
1. Pick the domain under which your certificates will be minted. The shorter the domain, the more data you can encode
in any given certificate. As an example, assume that I own the `example.com` domain. You could configure DNS so that
you use `example.com` directly for catlog, but for simplicity I'll choose the subdomain `x.example.com`.
1. Configure your domain (in this example `example.com`) so that the nameserver (NS) for the domain resolves to your
machine. In this example I might add these records to my `example.com` zone:

        catlog-ns.example.com.  IN A  192.168.0.10
        x.example.com.          IN NS catlog-ns.example.com.

1. Run `catlog config add-domain x.example.com`.

Now you can create a box, push a couple files to CT logs, and then commit your box (containing a listing of the files
uploaded) to CT logs:

# Quickstart Example: Pushing to CT Logs

```
# Create a new directory for our box and cd into it
$ mkdir mybox; cd mybox
# Initialize the working directory as a box
$ catlog init
# Copy some local files into our box's directory
$ cp ~/Documents/catpics/cat{1,2}.jpg .
# Upload cat1.jpg to CT logs
$ catlog push cat1.jpg
# Upload cat2.jpg to CT logs
$ catlog push cat2.jpg
# Commit our current box state (containing a list of pointers to files uploaded so far) to CT logs
$ catlog commit
# Get the log reference of our committed box
$ catlog status
Box log references
------------------
LCa0a2j/xo/5m0U8HTBBNBNCLXBkg7+g+YpeiGJm564=|/N4rLtula/QIYB+3If6bXDONEO5CnqBPrlURto+/j7k=
```

# Quickstart Example: Fetching from CT logs

CT logs generally have a 24 hour delay before certificates they have committed to adding are actually available in the
logs. So if you try to fetch contents immediately the request is likely to fail. However, after about 24 hours, you
should be able to clone the box on a new machine and download its contents.

```
# Create a new directory into which the box will be cloned
$ mkdir boxclone; cd boxclone
# Clone the box from CT logs
$ catlog clone 'LCa0a2j/xo/5m0U8HTBBNBNCLXBkg7+g+YpeiGJm564=|/N4rLtula/QIYB+3If6bXDONEO5CnqBPrlURto+/j7k='
# Get a list of files in the box
$ catlog status
Available but not fetched...
----------------------------
cat1.jpg
cat2.jpg
# Fetch a file
$ catlog pull cat2.jpg
# Look at cats!
$ xdg-open cat2.jpg
```

# Commands
The `catlog` command operates similarly to the "git" cli, with a number of similarly-named (but differently behaved)
subcommands.

## `catlog init box-name.example.com`
Initializes the current working directory as a cat box. When operating in an initialized directory catlog keeps
accounting of rate limits in effect, as well as the state of files in the box. The name can be used as a convenient
alias for later cloning the box.

## `catlog config`
This subcommand is going to be used to configure various aspects of catlog's operation, such as:
* Domains available for use
* Web root used for ACME domain verifications
* ...?

## `catlog clone <ref>`
Clones a box from the CT logs. This gets a listing of all files in the box, but does not actually download any of the
files.

## `catlog fetch`
Looks for any updates to the current box that's been committed to CT logs.

## `catlog pull <ref>`
If ref is a leaf hash, public key, DNS name, etc, this will download the file from CT logs and write it to stdout. If
the working directory is in a box, ref can be the filename of a Remote file, and it will be written to a file by the
same name.

## `catlog push <filename>`
Uploads a local (untracked) file to the CT logs. This will output the merkle hash of the file. If in a box, the file
will be staged. If a file is currently in a partially uploaded state, this will resume the upload.

## `catlog commit`
Pushes an update of current box to CT logs. All staged files will be come tracked.

## `catlog status`
Prints the current status of files in the box and any accounting information (e.g. how many commits remain in the week).

# CaTLog Design
Check out the [design docs](DESIGN.md) for some detailed information about the technical design of catlog.
