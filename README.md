# Postgres Protocol Implementation

#### What is this?
A simple and static one file postgres database wire protocol implementation. 

#### Motivation 

I don't see very often people implementing raw database protocol on transport layer directly i often see instead different Drivers/Connectors to postgres database. \
\
Which made me think: **How hard is it going to be ?!**

#### Competitors?

No, no, no i am not trying to build a new connector client. There are plenty of them already. 

My obsession with how the underlying stuff is working and how my prod-ready app communicates with a database and what are the behind the scenes of `userRepo.save(user)` (the java/spring realm) and enough curiosity made me do this.

Though. if you find this helpful for your next Postgres driver, then go ahead and fork it.

#### Because it's s a learning process...

I learned about dealing with TCP data directly from raw bytes. \
I exposed the internals of many well known drivers. \
I loved GO more. \
and most importantly \
I learned about the protocol of my favorite database. 

#### The real meat now.

This is a go implementation for the protocol that does only one single connection and one single query and halts. \
It is so simple, though i still didn't implement everything in the protocol just the main necessary parts:
* 1- connect 
* 2- authenticate 
* 3- send query 
* 4- parse and print the result set.
* 5- die.

You can adjust first few variable in the `main.go` file to connect and test it against your database. \
A simple `go run .` is enough to start.

#### Sources

* The official PostgreSQL protocol documentation: https://www.postgresql.org/docs/17/protocol.html

#### Contribute ?

I am open to fixes and additions because i am aware it is not perfect but it just works for now as a proof of concept. Feel free to open a pull request :)

#### Original Author: Ahmed Debbech