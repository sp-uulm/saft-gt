FROM ros:iron

RUN apt update && apt upgrade -y
RUN apt install -y \
        ssh openjdk-17-jre-headless \
        python3-requests \
        python3-pandas \
        python3-pip \
        libmariadb3 libmariadb-dev \
        docker.io

# no other chance to install mariadb for python3
RUN pip install mariadb      

# add helper scripts
ADD --chmod=700 scripts/* . 
  
ENTRYPOINT ["./ros_entrypoint.sh","./startup.sh"]
