PYApache
========

Description
-----------
Python Script that will exract unique ip address and ip address with country.
Note this is my project in GITHUB AND PYPI.

Installation
============

    pip install pyapache

Usage
==========
    import os
    from pyapache import ApacheParser
    AP = ApacheParser()
    AP.read_logfile(os.path.join(os.getcwd(), 'Logfile', 'sample.log'))
    AP.get_reslult(os.path.join(os.getcwd(), 'RESULT'))

