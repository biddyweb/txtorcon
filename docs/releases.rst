Releases
========

There isn't a "release schedule" in any sense. If there is something
in master your project depends upon, let me know and I'll do a
release. Starting with v0.8.0 versions are following `semantic
versioning <http://semver.org/>`_.

unreleased
----------

`git master <https://github.com/meejah/txtorcon>`_ *will likely become v0.9.3*


v0.9.2
------

*April 23, 2014*

 * `txtorcon-0.9.2.tar.gz <http://timaq4ygg2iegci7.onion/txtorcon-0.9.2.tar.gz>`_ (:download:`local-sig </../signatues/txtorcon-0.9.2.tar.gz.asc>` or `github-sig <https://github.com/meejah/txtorcon/blob/master/signatues/txtorcon-0.9.2.tar.gz.asc?raw=true>`_) (`source <https://github.com/meejah/txtorcon/archive/v0.9.2.tar.gz>`_)
 * add ``on_disconnect`` callback for TorControlProtocol (no more monkey-patching Protocol API)
 * add ``age()`` method to Circuit
 * add ``time_created`` property to Circuit
 * don't incorrectly listen for NEWDESC events in TorState
 * add ``.flags`` dict to track flags in Circuit, Stream
 * ``build_circuit()`` can now take hex IDs (as well as Router instances)
 * add ``unique_name`` property to Router (returns the hex id, unless ``Named`` then return name)
 * add ``location`` property to Router
 * ``TorState.close_circuit`` now takes either a Circuit ID or Circuit instance
 * ``TorState.close_stream`` now takes either a Stream ID or Stream instance
 * support both GeoIP API versions
 * more test-coverage
 * small patch from `enriquefynn <https://github.com/enriquefynn>`_ improving ``tor`` binary locating
 * strip OK lines in TorControlProtocol (see `issue #8 <https://github.com/meejah/txtorcon/issues/8>`_)
 * add ``api_version`` kwarg to TorControlProtocol
 * use TERM not KILL when Tor launch times out (see `issue #68 <https://github.com/meejah/txtorcon/pull/68>`_) from ``hellais``


v0.9.1
------

*January 20, 2014*

 * `txtorcon-0.9.1.tar.gz <http://timaq4ygg2iegci7.onion/txtorcon-0.9.1.tar.gz>`_ (:download:`local-sig </../signatues/txtorcon-0.9.1.tar.gz.asc>` or `github-sig <https://github.com/meejah/txtorcon/blob/master/signatues/txtorcon-0.9.1.tar.gz.asc?raw=true>`_) (`source <https://github.com/meejah/txtorcon/archive/v0.9.1.tar.gz>`_)
 * put test/ directory at the top level
 * using "`coverage <http://nedbatchelder.com/code/coverage/>`_" tool instead of custom script
 * using `coveralls.io <https://coveralls.io/r/meejah/txtorcon>`_ and `travis-ci <https://travis-ci.org/meejah/txtorcon>`_ for test coverage and continuous integration
 * `issue #56 <https://github.com/meejah/txtorcon/issues/56>`_: added Circuit.close() and Stream.close() starting from aagbsn's patch
 * parsing issues with multi-line keyword discovered and resolved
 * preserve router nicks from long-names if consensus lacks an entry (e.g. bridges)
 * using `Twine <https://github.com/dstufft/twine>`_ for releases
 * `Wheel <http://wheel.readthedocs.org/en/latest/>`_ release now also available
 * `issue #57 <https://github.com/meejah/txtorcon/issues/57>`_: "python setup.py develop" now supported
 * `issue #59 <https://github.com/meejah/txtorcon/pull/59>`_: if tor_launch() times out, Tor is properly killed (starting with pull-request from Ryman)
 * experimental docker.io-based tests (for HS listening, and tor_launch() timeouts)
 * `issue #55 <https://github.com/meejah/txtorcon/issues/55>`_: pubkey link on readthedocs
 * `issue #63 <https://github.com/meejah/txtorcon/issues/55>`_
 * clean up GeoIP handling, and support pygeoip both pre and post 0.3
 * slightly improve unit-test coverage (now at 97%, 61 lines of 2031 missing)
 * added a `Walkthrough <walkthrough.html>`_ to the documentation


v0.8.2
------

*November 22, 2013*

 * `txtorcon-0.8.2.tar.gz <http://timaq4ygg2iegci7.onion/txtorcon-0.8.2.tar.gz>`_ (:download:`local-sig </../signatues/txtorcon-0.8.2.tar.gz.asc>` or `github-sig <https://github.com/meejah/txtorcon/blob/master/signatues/txtorcon-0.8.2.tar.gz.asc?raw=true>`_) (`source <https://github.com/meejah/txtorcon/archive/v0.8.2.tar.gz>`_)
 * ensure hidden service server-side endpoints listen only on 127.0.0.1


v0.8.1
------

*May 13, 2013*

 * `txtorcon-0.8.1.tar.gz <http://timaq4ygg2iegci7.onion/txtorcon-0.8.1.tar.gz>`_ (:download:`local-sign </../signatues/txtorcon-0.8.1.tar.gz.sig>` or `github-sig <https://github.com/meejah/txtorcon/blob/master/signatues/txtorcon-0.8.1.tar.gz.sig?raw=true>`_) (`source <https://github.com/meejah/txtorcon/archive/v0.8.1.tar.gz>`_)
 * fixed improper import in setup.py preventing 0.8.0 from installing
 * signatures with proper subkey this time
 * Proper file-flushing in tests and PyPy fixes from Lukas Lueg
 * docs build issue from isis

v0.8.0
------

*April 11, 2013* (actually uploaded May 11)

 * **Please use 0.8.1; this won't install due to import problem in setup.py (unless you have pypissh).**
 * following `semantic versioning <http://semver.org/>`_;
 * slight **API change** :meth:`.ICircuitListener.circuit_failed`, :meth:`~.ICircuitListener.circuit_closed` and :meth:`.IStreamListener.stream_failed`, :meth:`~.IStreamListener.stream_closed` and :meth:`~.IStreamListener.stream_detach` all now include any keywords in the notification method (some of these lacked flags, or only included some) (`issue #18 <https://github.com/meejah/txtorcon/issues/18>`_);
 * launch_tor() can take a timeout (starting with a patch from hellais);
 * cleanup from aagbsn;
 * more test coverage;
 * run tests cleanly without graphviz (from lukaslueg);
 * `issue #26 <https://github.com/meejah/txtorcon/issues/26>`_ fix from lukaslueg;
 * pep8 and whitespace targets plus massive cleanup (now pep8 clean, from lukaslueg);
 * `issue #30 <https://github.com/meejah/txtorcon/issues/30>`_ fix reported by webmeister making ipaddr actually-optional;
 * example using synchronous web server (built-in SimpleHTTPServer) with txtorcon (from lukaslueg);
 * TorState can now create circuits without an explicit path;
 * passwords for non-cookie authenticated sessions use a password callback (that may return a Deferred) instead of a string (`issue #44 <https://github.com/meejah/txtorcon/issues/44>`_);
 * fixes for AddrMap in case `#8596 <https://trac.torproject.org/projects/tor/ticket/8596>`_ is implemented;

v0.7
----

*November 21, 2012*

 * `txtorcon-0.7.tar.gz <http://timaq4ygg2iegci7.onion/txtorcon-0.7.tar.gz>`_ (:download:`local-sig <../signatues/txtorcon-0.7.tar.gz.sig>` or `github-sig <https://github.com/meejah/txtorcon/blob/master/signatues/txtorcon-0.7.tar.gz.sig?raw=true>`_) (`source <https://github.com/meejah/txtorcon/tarball/v0.7>`_)
 * `issue #20 <https://github.com/meejah/txtorcon/issues/20>`_ config object now hooked up correctly after launch_tor();
 * `patch <https://github.com/meejah/txtorcon/pull/22>`_ from hellais for properly handling data_dir given to TCPHiddenServiceEndpoint;
 * `.tac example <https://github.com/meejah/txtorcon/pull/19>`_ from mmaker;
 * allow TorConfig().hiddenservices.append(hs) to work properly with no attached protocol

v0.6
----

*October 10, 2012*

 * `txtorcon-0.6.tar.gz <http://timaq4ygg2iegci7.onion/txtorcon-0.6.tar.gz>`_ (:download:`local-sig <../signatues/txtorcon-0.6.tar.gz.sig>` or `github-sig <https://github.com/meejah/txtorcon/blob/master/signatues/txtorcon-0.6.tar.gz.sig?raw=true>`_) (`source <https://github.com/meejah/txtorcon/tarball/v0.6>`_)
 * debian packaging (mmaker);
 * psutil fully gone;
 * *changed API* for launch_tor() to use TorConfig instead of args;
 * TorConfig.save() works properly with no connected Tor;
 * fix incorrect handling of 650 immediately after connect;
 * `pep8 compliance <http://www.python.org/dev/peps/pep-0008/>`_;
 * use assertEqual in tests;
 * messages with embdedded keywords work properly;
 * fix bug with setup.py + pip;
 * `issue #15 <https://github.com/meejah/txtorcon/issues/15>`_ reported along with patch by `Isis Lovecruft <https://github.com/isislovecruft>`_;
 * consolidate requirements (from `aagbsn <https://github.com/aagbsn>`_);
 * increased test coverage and various minor fixes;
 * https URIs for ReadTheDocs;

v0.5
----
June 20, 2012

 * `txtorcon-0.5.tar.gz <txtorcon-0.5.tar.gz>`_ (`txtorcon-0.5.tar.gz.sig <txtorcon-0.5.tar.gz.sig>`_) (`source <https://github.com/meejah/txtorcon/tarball/v0.5>`_)
 * remove psutil as a dependency, including from `util.process_from_address`

v0.4
----
June 6, 2012

 * `txtorcon-0.4.tar.gz <txtorcon-0.4.tar.gz>`_ (`txtorcon-0.4.tar.gz.sig <txtorcon-0.4.tar.gz.sig>`_)
 * remove built documentation from distribution; 
 * fix PyPI problems ("pip install txtorcon" now works)

v0.3
----
 * 0.3 was broken when released (docs couldn't build).

v0.2
----
June 1, 2012

 * `txtorcon-0.2.tar.gz <txtorcon-0.2.tar.gz>`_ (`txtorcon-0.2.tar.gz.sig <txtorcon-0.2.tar.gz.sig>`_)
 * incremental parsing;
 * faster TorState startup;
 * SAFECOOKIE support;
 * several bug fixes;
 * options to :ref:`circuit_failure_rates.py` example to make it actually-useful;
 * include built documentation + sources in tarball;
 * include tests in tarball;
 * improved logging;
 * patches from `mmaker <https://github.com/mmaker>`_ and `kneufeld <https://github.com/kneufeld>`_;

v0.1
----
march, 2012

 * `txtorcon-0.1.tar.gz <txtorcon-0.1.tar.gz>`_ (`txtorcon-0.1.tar.gz.sig <txtorcon-0.1.tar.gz.sig>`_)

