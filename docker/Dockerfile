#Docker Static File Analysis (SFA)
FROM debian:latest
MAINTAINER Lionel PRAT <lionel.prat9@gmail.com>

RUN apt-get update && apt-get install -y build-essential git python-pip libjson-c-dev libxml2-dev libssl-dev libbz2-dev python-dev python-virtualenv xdot openssl vim zlib1g-dbg zlib1g zlib1g-dev cron
RUN cd /opt/ && git clone https://github.com/lprat/static_file_analysis
RUN cd /opt/static_file_analysis && git clone https://github.com/vrtadmin/clamav-devel
RUN cd /opt/static_file_analysis/clamav-devel && ./configure --enable-static --with-libjson && make
#bug to install hashlib
RUN rm -f /usr/lib/python2.7/lib-dynload/_hashlib.x86_64-linux-gnu.so
#install hashlib pydot yara flask
RUN pip install pydot yara-python hashlib flask gunicorn
#make auto signed cert
RUN cd /opt/static_file_analysis/api && openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365  -subj '/CN=localdomain/O=SFA/C=FR'

#add script to update git
ADD git_update.sh /opt/git_update.sh
RUN chmod 0755 /opt/git_update.sh
# Add crontab file in the cron directory
ADD crontab_update /etc/cron.d/git-update-cron
# Give execution rights on the cron job
RUN chmod 0644 /etc/cron.d/git-update-cron

#add entrypoint
ADD docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod 0700 /docker-entrypoint.sh
WORKDIR /opt/static_file_analysis/

EXPOSE 8000
ENTRYPOINT ["/docker-entrypoint.sh"]
#CMD ["git pull;/bin/bash"]
