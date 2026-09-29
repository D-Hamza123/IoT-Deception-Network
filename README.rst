IoT Deception Network
#####################

An experimental, multi-service honeypot lab for collecting and reviewing
network attack activity. It combines SSH/Telnet deception with IoT and common
protocol services, then provides a small dashboard for exploring observed
events and preparing (not applying) firewall block rules.

This repository includes a customized `Cowrie <https://github.com/cowrie/cowrie>`_
SSH/Telnet honeypot codebase, a Docker Compose setup for Cowrie and Dionaea, and
a Streamlit analysis app. Cowrie is upstream software; this repository's project
integration and dashboard are the focus here.

.. contents:: On this page
     :local:
     :depth: 2

What It Does
------------

The system is designed to attract and observe unsolicited connections without
exposing production services. Instead of granting access to real infrastructure,
honeypots provide monitored, disposable-looking services that record connection
attempts and interactions for later analysis.

* **Cowrie** listens for SSH and Telnet activity. Its default shell backend
    emulates a Linux environment and records attempted credentials, commands,
    sessions, and transferred files. Cowrie also supports proxying to a real or
    virtual backend, but proxy mode needs separate, carefully isolated setup.
* **Dionaea** provides additional network-facing services. The root Compose file
    currently declares FTP, SMB, MQTT, and HTTP-related exposure through its
    Dionaea container.
* **The Streamlit dashboard** reads Cowrie's JSON event log and a Dionaea SQLite
    database, then shows SSH login/command activity and IoT/service probe activity.
    It can generate Cisco IOS ACL text for the most active Cowrie source IPs. The
    app only displays the commands; it does not apply firewall changes.
* **Optional Cowrie backend pool** uses QEMU/libvirt virtual machines to give
    proxy sessions isolated guest environments. It is an advanced, separately
    configured feature and is not started by the root Compose file.

How Data Flows
--------------

1. Clients connect to the exposed honeypot ports.
2. Cowrie records structured events in ``var/log/cowrie/cowrie.json`` and keeps
     session recordings and captured downloads under ``var/lib/cowrie/``.
3. Dionaea writes its own service data to its configured storage. The dashboard
     expects that data to be available as ``dionaea_iot.sqlite`` in the project
     root, with a ``connections`` table containing ``connection_timestamp``,
     ``remote_host``, and ``local_port`` columns.
4. Run the dashboard locally to inspect the available data and generate a
     candidate blocklist for review by an operator.

The supplied Compose file persists Dionaea data in a Docker named volume; it
does **not** create or export the SQLite file expected by the dashboard. You
must provide/populate that database yourself before Dionaea charts will contain
data. The dashboard can still display Cowrie data independently.

Quick Start
-----------

Requirements
~~~~~~~~~~~~

* Docker Engine and the Docker Compose plugin.
* A Linux host is recommended for the supplied Dionaea configuration, which
    uses host networking. Docker Desktop networking differs from native Linux.
* Python 3 and pip only if you want to run the dashboard.

Start the honeypots
~~~~~~~~~~~~~~~~~~~

From the repository root, review ``docker-compose.yml`` and then start the
services:

.. code-block:: console

     docker compose up -d
     docker compose ps
     docker compose logs -f cowrie dionaea

Cowrie is published on host ports ``2222`` (SSH) and ``2223`` (Telnet). For a
local smoke test, connect over SSH:

.. code-block:: console

     ssh -p 2222 root@127.0.0.1

This is a honeypot interaction, not a real host login. To stop the services:

.. code-block:: console

     docker compose down

The root Compose file does not publish Dionaea ports with ordinary port
bindings: the Dionaea service uses ``network_mode: host``. On Linux, its
configured listeners use host networking; inspect and adjust the service
configuration for the target platform before exposing it.

Run the dashboard
~~~~~~~~~~~~~~~~~

Install its app dependencies into an isolated environment and launch Streamlit:

.. code-block:: console

     python3 -m venv .venv
     source .venv/bin/activate
     python -m pip install --upgrade pip
     python -m pip install streamlit pandas plotly
     streamlit run app.py

The dashboard looks for ``var/log/cowrie/cowrie.json`` and
``dionaea_iot.sqlite`` relative to the repository root. Cowrie's volume is
bind-mounted there by the root Compose file. If the dashboard reports no events,
check that Cowrie has received connections and that the expected files and
SQLite schema are present.

Configuration and Operations
-----------------------------

* Cowrie overrides belong in ``etc/cowrie.cfg``. Keep defaults in
    ``etc/cowrie.cfg.dist`` unchanged; local settings override them. See
    `Installation <docs/INSTALL.rst>`_ and the
    `configuration reference <https://docs.cowrie.org/en/latest/04_CONFIG/Configuration.html>`_.
* Cowrie JSON and application logs are under ``var/log/cowrie/``. Session
    recordings and downloaded artifacts are under ``var/lib/cowrie/``; treat
    captured files as untrusted malware samples.
* For Cowrie proxy mode and backend selection, see
    `Proxy documentation <docs/PROXY.rst>`_. For the optional QEMU/libvirt pool,
    see `Backend Pool documentation <docs/BACKEND_POOL.rst>`_.
* Output integrations and deployment guides are in ``docs/``. The dashboard's
    Python dependencies are not part of Cowrie's ``requirements.txt``.

Security and Responsible Deployment
-----------------------------------

Honeypots are intentionally reachable and may attract hostile traffic. Run them
only on systems and networks you control or are authorized to monitor.

* Do not expose this stack on a trusted internal network. Put it behind an
    isolated network boundary and restrict outbound access, especially if you
    enable Cowrie proxy mode or connect a backend VM.
* Do not run Cowrie as root. Use firewall rules and least-privilege service
    accounts, and review the Compose network and volume settings before deployment.
* The Compose file uses ``restart: always`` and the Dionaea container uses host
    networking. Understand those implications and the ports being exposed before
    starting it on a public host.
* Logs can contain attacker IP addresses, submitted credentials, commands, and
    transferred files. Protect, retain, and share this data according to your
    organization's policy and applicable law.
* The generated Cisco ACL is only a starting point. Validate addresses, rule
    order, interface, and operational impact before applying it to a router.

Documentation
-------------

* `Cowrie documentation <https://docs.cowrie.org/en/latest/index.html>`_
* `Installation guide <docs/INSTALL.rst>`_
* `Proxy mode <docs/PROXY.rst>`_
* `Backend pool <docs/BACKEND_POOL.rst>`_
* `Output integrations <docs/OUTPUT.rst>`_
* `Contributing <CONTRIBUTING.rst>`_

About Cowrie
------------

Cowrie is an open-source medium- to high-interaction SSH and Telnet honeypot.
In shell mode it emulates a Unix-like environment; in proxy mode it forwards
sessions to a configured backend. This repository contains Cowrie-derived and
Cowrie-maintained code alongside the IoT Deception Network integration.

For upstream Cowrie releases, community support, and project history, visit
`the Cowrie project <https://github.com/cowrie/cowrie>`_ and
`Cowrie documentation <https://docs.cowrie.org/>`_.

License
-------

See `LICENSE.rst <LICENSE.rst>`_ for the license and attribution details.
