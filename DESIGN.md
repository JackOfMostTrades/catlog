CaTLog Design Docs
==================
_For putting cats in your CTLog_

# Overview

This document attempts to describe the intended implementation of the "catlog" tool for downloading and uploading files
from/to CT logs. Putting data into CT logs has two unique constraints:

* By nature, it is append-only.
* There are rate limits on the number of certificates that can be minted. These limits are generous in the context of
being able to mint publicly trusted certs as intended, but they are low enough that we have to be especially careful
with how many times we can "commit" data to the CT logs.

Given these constraints, we model the catlog tool after git. Git works well under these conditions given that it too
operates in an "append-only" commit history and given that one's working directory has staged operations that eventually
get committed to its revision history in a single operation.

While we could model catlog's operation directly on git, we choose to make a few simplifications. In doing so, we are
able to host and link to individual files in the CT logs (rather than entire repos).

## Boxes
Like S3 buckets, catlog files can be collected together into a collection called a _box_. A box is simply a collection
of file references which include the name of the file and a pointer to its location in the CT logs. Given that the
reference is a pointer, a file can be shared between many boxes. As with S3, boxes are just a listing of files (and are
not inherently organized into a directory tree structure) but file names can contain slashes so that they are fetched
into a directory tree when downloaded with catlog.

## Working Directory
Catlog supports uploading and fetching individual files, in which case there is no local state maintained. However, when
a directory is initialized as a box it operates in a manner similar to a git repo where files in the directory can be in
several different states and can eventually be committed to the box.

When working in an initialized box, a file exists in one of four states while on a local system:
* Untracked (meaning it is only local)
* Partially uploaded (for files which are too big to push immediately to CT logs)
* Staged (for files which are completely uploaded but are not added to the box)
* Tracked (when all files added to the box are committed and added to the box in the CT log)
* Remote (for files which are tracked in the box, but which have not been downloaded from the CT logs)

## CT References
A certificate in CT logs can be universally and uniquely referred to by CT log APIs by its leaf hash. This is the
preferred way to reference files/boxes in CT logs since lookups can be done utilizing CT log servers exclusively.

However, a number of services (such as crt.sh) also support searching for certificates by public key, DNS name, and
other terms. For convenience, catlog will also generally support references made by these alternate identifiers.

# Commands
As with the "git" cli, catlog has a number of subcommands.

## `catlog init`
Initializes the current working directory as a cat box. When operating in an initialized directory catlog keeps
accounting of rate limits in effect, as well as the state of files in the box.

## `catlog config`
This subcommand is going to be used to configure various aspects of catlog's operation, such as:
* Domains available for use
* Web root used for ACME domain verifications
* ...?

## `catlog clone <ref>`
Clones a box from the CT logs. This gets a listing of all files in the box, but does not actually download any of the
files.

## `catlog fetch <ref>`
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

# Accounting
All catlog operations which need to push certificates to CT logs will be recorded. This will be utilized to determine
whether or not a operation can be completed without going over rate limits. It will also be used to manage partial
uploads. Most operations will display accounting information (e.g. how many certificates can still be used and how many
certificates will be consumed to push a file/box).

# Data Encoding
We encode data into the SANs of a certificate. We do this by chunking the data, base32 encoding it, and prepending it
as a subdomain. While the LetsEncrypt CA generally preserves the order of SANs as we encode them in the CSR, this is
not strictly guaranteed. Therefore we use the first decoded byte of each SAN as an ordinal to indicate its placement in
the chunk ordering.

In order to chunk data across certificates and encode box data, we need to apply some additional structure on top of
the raw binary data we may be putting into the certificate. We choose to encode data using protobuf since it makes it
easy to efficiently encode structured binary data. View [catlog.proto](catlog.proto) for the proto definition we use,
including some detailed comments explaining the structure.

Note that when we chunk data, each chunk points to the previous chunk (since we do not know a chunk's leaf-hash until
it has been uploaded). Therefore we point to files by pointing to the leaf-hash of the last chunk of a file. Similarly,
we point to the latest revision of a box by pointing to its last chunk. When we commit a box revision we simply upload
one or more new box chunks, pointing to the latest file-hash when doing so.

Note that in this scheme we do not have a way, given our box's current leaf-hash, of discovering if there is a newer
box-chunk available in the CT logs. We may want to utilize some additional part of the subject or public key so that
using non-standardized APIs we might search for newer certificates representing box chunks.

