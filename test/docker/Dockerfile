FROM alpine:3.21
RUN apk add --no-cache openssh-server bash && \
    ssh-keygen -A && \
    mkdir -p /root/.ssh && \
    chmod 700 /root/.ssh && \
    echo "root:testpassword" | chpasswd && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config && \
    mkdir -p /var/log && echo "test log line 1\ntest log line 2\ntest log line 3" > /var/log/test.log && \
    mkdir -p /tmp/testdir && touch /tmp/testdir/file1.txt /tmp/testdir/file2.log /tmp/testdir/file3.txt
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
