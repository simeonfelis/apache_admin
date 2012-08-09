apache\_admin
=============

apache\_admin will help you organize your projects and the access to it. It is a
rights management tool which lets you controll access to services based on
projects. E.g. you can add projects to users who are involved, and then they have
access for e.g. a BZR repository and DAV share, which belongs to the project.

The ideal use case for apache\_admin is:

  *   You have many users and projects (>10)
  *   You don't want to give users ssh access to your server
  *   You prefer offering http(s) only access
  *   You want to offer different VCS in combination with Dav shares and wikis
      and maybe more
  *   All services should be operated with the same username and password


Features
========

  *   Generates config files for apache for Bazaar, Dav, Git, SVN
  *   Generates password file for apache
  *   Generates group file for apache
  *   Can optionally handle jabber-accounts through ejabberd
  *   Right management based on users belonging to projects
  *   A todo/ticket system for managing tasks (Thanks to shaker:
      https://github.com/shacker/django-todo)


Prerequisites
=============

  *  python > 2.5
  *  django 1.4
  *  python hashlib
  *  sqlite (or what db backend you prefer)

Install
=======

Install this package completely or only the apache\_admin and todo app:
  *   add "apache\_admin" and "todo" to your "installed\apps" section in
      settings.py
  *   make sure you had fit your settings.py according to, e.g.
      settings\_dev\_simeon.py
  *   Make the directory "generated" writable for apache user
  *   symlink desired config files from
      /etc/apache2/conf.d/dav.conf -> /path/to/deployment/generated/dav.conf
  *   Add a cron job every minute to do the maintenance call, which eventually
      generates config files, password file and group file for apache and
      requests apache to reload its settings.
  *   Fit your paths in the apache/makefile

In any case run `./manage.py syncdb` to geneate the new db or add tables to existing ones.

About the maintenance call every minute:
You can set up a cronjob every minute like this:
in /etc/crontab add:

    *  *    * * *   root    /root/maintenance.sh > /dev/null

The script /root/maintenance.sh could look like this:

    #!/bin/bash

    cd /path/to/deployment/apache/
    RET=$?
    if [ $RET -ne 0 ] ; then
        echo "Could not cd into deploy path" 1>&2
        exit
    fi

    make --quiet

Known issues
============

  *   Well, maybe the maintenance url should be password protected
  *   translation support is very rudimentary. You will have a mix
      of German and English.
  *   Some URLs in templates are hard coded. You should check every template or
      grep for `regensburg` or `las3`
  *   sending emails will not work unless the sender has `regensburg` in his mail address
  *   I have yet to decide for a licence. Don't worry, it'l be cool.


