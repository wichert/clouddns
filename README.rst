Cloud DNS management tool
=========================

This package implements a console script that can be used to to perform
some basic management tasks for the Rackspace Cloud DNS service.

To use the ``clouddns`` script you need to know your username and the API key.
You can find the API key in the *API Access* section of the Rackspace Cloud
Control Portal.

::

    $ bin/clouddns --username=wichert --api=807ab61566324dc036493b306fe86eb1 list 
    wiggy.net id=3201843
    $ bin/clouddns --username=wichert --api=807ab61566324dc036493b306fe86eb1 dump wiggy.net
    wiggy.net	7200	A	82.94.255.193
    wiggy.net	7200	AAAA	2001:888:2003:1011::10
    wiggy.net	7200	MX	mx1.simplon.biz
    wiggy.net	7200	NS	dns1.stabletransit.com
    wiggy.net	7200	NS	dns2.stabletransit.com
    www.wiggy.net	7200	A	82.94.255.193
    www.wiggy.net	7200	AAAA	2001:888:2003:1011::10
 
If you are using a UK based account you must use the ``--region`` parameter:
::

    $ bin/clouddns --username=wichert --api=807ab61566324dc036493b306fe86eb1 --region=uk list 
    wiggy.net id=3201843

You can easily migrate an existing domain by importing its bind zone file. When
you are doing this make sure the record names are absolute so the cloud dns
platform can figure out which domain you are importing. The above domain was
imported from this file zone::

    wiggy.net.      IN      SOA     levante.wiggy.net. hostmaster.wiggy.net.  2010110601 86400 7200 2419200 7200 
                    IN      MX      10 mx1.simplon.biz.
       		IN	A	82.94.255.193
    		IN	AAAA	2001:888:2003:1011::10
    
    $ORIGIN wiggy.net.
    www		IN	A	82.94.255.193
    		IN	AAAA	2001:888:2003:1011::10

using this command::

    $ bin/clouddns --username=wichert --api=807ab61566324dc036493b306fe86eb1 import-zone net.wiggy
