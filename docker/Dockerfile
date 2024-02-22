FROM ubuntu:22.04

WORKDIR /root

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=

# fix all the hash sum errors
# potential solutions:
# [failed] https://stackoverflow.com/questions/48645936/
# [worked] https://stackoverflow.com/questions/67732260/
RUN echo "Acquire::http::Pipeline-Depth 0;" > /etc/apt/apt.conf.d/99custom  \
    && echo "Acquire::http::No-Cache true;" >> /etc/apt/apt.conf.d/99custom \
    && echo "Acquire::BrokenProxy    true;" >> /etc/apt/apt.conf.d/99custom

RUN set -eux \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/* \
	&& apt-get update -o Acquire::CompressionTypes::Order::=gz --fix-missing

##################################################
# install eclipse temurin and gradle
# dockerfile source url (eclipse-temurin:17-jdk-jammy):
# https://github.com/adoptium/containers/blob/920efae8fe37e2b8f2b288b5f7f9e67134ecad1d/17/jdk/ubuntu/jammy/Dockerfile.releases.full

# set relevant environment variables
# note: the java version variable isn't actually used
ENV JAVA_VERSION=jdk-17.0.7+7
ENV JAVA_HOME=/opt/java/openjdk
ENV PATH=${JAVA_HOME}/bin:$PATH

# set file encoding
ENV LANG='en_US.UTF-8' LANGUAGE='en_US:en' LC_ALL='en_US.UTF-8'

# install dependencies
RUN apt-get install -y --no-install-recommends \
		tzdata \
		curl \
		wget \
		ca-certificates \
		fontconfig \
		locales \
		binutils \
	&& echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen \
	&& locale-gen en_US.UTF-8
	# && rm -rf /var/lib/apt/lists/*

# install temurin openjdk
RUN set -eux; \
    ARCH="$(dpkg --print-architecture)"; \
    case "${ARCH}" in \
		aarch64|arm64) \
			ESUM='0084272404b89442871e0a1f112779844090532978ad4d4191b8d03fc6adfade'; \
			BINARY_URL='https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.7%2B7/OpenJDK17U-jdk_aarch64_linux_hotspot_17.0.7_7.tar.gz'; \
			;; \
		armhf|arm) \
			ESUM='e7a84c3e59704588510d7e6cce1f732f397b54a3b558c521912a18a1b4d0abdc'; \
			BINARY_URL='https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.7%2B7/OpenJDK17U-jdk_arm_linux_hotspot_17.0.7_7.tar.gz'; \
			;; \
		ppc64el|powerpc:common64) \
			ESUM='8f4366ff1eddb548b1744cd82a1a56ceee60abebbcbad446bfb3ead7ac0f0f85'; \
			BINARY_URL='https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.7%2B7/OpenJDK17U-jdk_ppc64le_linux_hotspot_17.0.7_7.tar.gz'; \
			;; \
		s390x|s390:64-bit) \
			ESUM='2d75540ae922d0c4162729267a8c741e2414881a468fd2ce4140b4069ba47ca9'; \
			BINARY_URL='https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.7%2B7/OpenJDK17U-jdk_s390x_linux_hotspot_17.0.7_7.tar.gz'; \
			;; \
		amd64|i386:x86-64) \
			ESUM='e9458b38e97358850902c2936a1bb5f35f6cffc59da9fcd28c63eab8dbbfbc3b'; \
			BINARY_URL='https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.7%2B7/OpenJDK17U-jdk_x64_linux_hotspot_17.0.7_7.tar.gz'; \
			;; \
		*) \
			echo "Unsupported arch: ${ARCH}"; \
			exit 1; \
			;; \
    esac; \
	wget -O /tmp/openjdk.tar.gz ${BINARY_URL}; \
	echo "${ESUM} */tmp/openjdk.tar.gz" | sha256sum -c -; \
	mkdir -p "$JAVA_HOME"; \
	tar --extract \
		--file /tmp/openjdk.tar.gz \
		--directory "$JAVA_HOME" \
		--strip-components 1 \
		--no-same-owner \
	; \
    rm -f /tmp/openjdk.tar.gz ${JAVA_HOME}/src.zip; \
# https://github.com/docker-library/openjdk/issues/331#issuecomment-498834472
    find "$JAVA_HOME/lib" -name '*.so' -exec dirname '{}' ';' | sort -u > /etc/ld.so.conf.d/docker-openjdk.conf; \
    ldconfig; \
# https://github.com/docker-library/openjdk/issues/212#issuecomment-420979840
# https://openjdk.java.net/jeps/341
    java -Xshare:dump;

RUN echo Verifying install ... \
    && fileEncoding="$(echo 'System.out.println(System.getProperty("file.encoding"))' | jshell -s -)"; [ "$fileEncoding" = 'UTF-8' ]; rm -rf ~/.java \
    && echo javac --version && javac --version \
    && echo java --version && java --version \
    && echo "java install complete."


##################################################
# install gradle
# necessary for installing ghidrathon
# dockerfile source url (gradle:jdk17)
# https://github.com/keeganwitt/docker-gradle/blob/master/jdk17/Dockerfile

ARG GRADLE_VERSION=8.2.1
ARG GRADLE_SHA256=03ec176d388f2aa99defcadc3ac6adf8dd2bce5145a129659537c0874dea5ad1

ENV GRADLE_HOME=/opt/gradle
ENV PATH=${GRADLE_HOME}/bin:$PATH

# install dependencies
RUN set -eux \
	&& apt-get install -y --no-install-recommends \
		unzip \
		# wget \
		bzr \
		git \
		git-lfs \
		mercurial \
		openssh-client \
		subversion \
	# && rm -rf /var/lib/apt/lists/* \
	&& echo "testing vcs ..." \
	&& which bzr \
	&& which git \
	&& which git \
	&& which git-lfs \
	&& which hg  \
	&& which svn

# install gradle
RUN set -eux \
	&& echo "downloading gradle ..." \
	&& wget -O /tmp/gradle.zip "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip" \
	\
	&& echo "check download hash ..." \
	&& echo "${GRADLE_SHA256} /tmp/gradle.zip" | sha256sum --check - \
	\
	&& echo "installing gradle ..." \
	&& unzip -d /tmp/ /tmp/gradle.zip \
	&& rm /tmp/gradle.zip \
	&& mv "/tmp/gradle-${GRADLE_VERSION}" "${GRADLE_HOME}" \
	\
	&& echo "testing gradle installation ..." \
	&& gradle --version \
	&& echo "gradle install complete."


##################################################
# install mamba
# dockerfile source url (condaforge/mambaforge):
# https://github.com/conda-forge/miniforge-images/blob/master/ubuntu/Dockerfile

ARG CONDA_NAME=Mambaforge
ARG CONDA_VERSION=latest

ENV CONDA_DIR=/opt/conda
ENV PATH=${CONDA_DIR}/bin:$PATH

# download mambaforge and install
RUN set -eux \
	&& apt-get install -y --no-install-recommends \
		# wget \
		bzip2 \
		# ca-certificates \
		# git \
		tini \
	# && apt-get clean \
	&& rm -rf /var/lib/apt/lists/* \
	&& wget --no-hsts -O /tmp/miniforge.sh \
		"https://github.com/conda-forge/miniforge/releases/latest/download/Mambaforge-$(uname)-$(uname -m).sh" \
	&& /bin/bash /tmp/miniforge.sh -b -p ${CONDA_DIR} \
	&& rm /tmp/miniforge.sh \
	&& conda clean --tarballs --index-cache --packages --yes \
	&& find ${CONDA_DIR} -follow -type f -name '*.a' -delete \
	&& find ${CONDA_DIR} -follow -type f -name '*.pyc' -delete \
	&& conda clean --force-pkgs-dirs --all --yes \
	&& echo ". ${CONDA_DIR}/etc/profile.d/conda.sh && conda activate base" >> /etc/skel/.bashrc \
    && echo ". ${CONDA_DIR}/etc/profile.d/conda.sh && conda activate base" >> ~/.bashrc \
    && echo "mamba install complete."

SHELL ["/bin/bash", "--login", "-c"]


# set up base environment
RUN set -eux \
	&& mamba install -y -c conda-forge \
		python=3.10 \
		pip \
	&& pip install requests


##################################################
# install ghidra and ghidrathon

ARG GHIDRA_VERSION=10.3.2_PUBLIC
ARG GHIDRA_SHA256=a658677a87d0be12ab65bd7962f471875b81a2dd2ea35d69cc3201555ca1bd6f
ARG GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.3.2_build/ghidra_10.3.2_PUBLIC_20230711.zip

ENV GHIDRA_HOME=/opt/ghidra
ENV GHIDRATHON_HOME=/opt/ghidrathon

# install dependencies
RUN set -eux \
	&& apt-get update \
	&& apt-get install -y --no-install-recommends \
		# unzip \
		# curl \
		# git \
		bison \
		flex \
		build-essential

# install ghidra binaries
RUN set -eux \
	&& apt-get install -y --no-install-recommends \
		fontconfig \
		libxrender1 \
		libxtst6 \
		libxi6 \
		xorg \
		xvfb \
		# wget \
		# unzip \
		# python3-requests \
    && wget --progress=bar:force -O /tmp/ghidra.zip ${GHIDRA_URL} \
    && echo "$GHIDRA_SHA256 /tmp/ghidra.zip" | sha256sum -c - \
    && unzip /tmp/ghidra.zip \
    && rm /tmp/ghidra.zip \
    && mv ghidra_${GHIDRA_VERSION} $GHIDRA_HOME \
    && chmod +x \
    	${GHIDRA_HOME}/ghidraRun \
    	${GHIDRA_HOME}/support/analyzeHeadless \
    	${GHIDRA_HOME}/support/buildNatives 
    # && xhost +local:

RUN ${GHIDRA_HOME}/support/buildNatives

# add ghidra binaries to path
ENV PATH=${GHIDRA_HOME}:${GHIDRA_HOME}/support:$PATH

# ghidra broken without a DISPLAY variables
# need to use Xvfb to provide a virtual X11 server
RUN Xvfb :99 &
ENV DISPLAY=:99

RUN echo "ghidra install complete."

# create ghidra python environment
COPY envs/ghidra.yml ./envs/ghidra.yml
RUN set -eux \
	&& mamba env create -f envs/ghidra.yml

SHELL [ "conda", "run", "-n", "ghidra", "/bin/bash", "-c" ]

# install ghidrathon
RUN set -eux \
	# && conda activate ghidra \
	&& wget -O Ghidrathon.zip "https://github.com/mandiant/Ghidrathon/releases/download/v4.0.0/Ghidrathon-v4.0.0.zip" \
	&& unzip -d $GHIDRATHON_HOME Ghidrathon.zip \
	&& rm Ghidrathon.zip \
	&& cd $GHIDRATHON_HOME \
	&& python ghidrathon_configure.py $GHIDRA_HOME \
	&& unzip -d ${GHIDRA_HOME}/Ghidra/Extensions ${GHIDRATHON_HOME}/\*.zip \
	&& echo "ghidrathon install complete."

SHELL ["/bin/bash", "--login", "-c"]


##################################################
# install ffxe dependencies

COPY envs/ffxe.yml ./envs/ffxe.yml
COPY envs/plot.yml ./envs/plot.yml
COPY envs/angr.yml ./envs/angr.yml
RUN set -eux \
	&& mamba env create -f envs/ffxe.yml \
	&& mamba env create -f envs/plot.yml \
	&& mamba env create -f envs/angr.yml 


##################################################
# install firmxray

ENV FIRMXRAY_HOME=/opt/firmxray

RUN set -eux \
	&& mkdir ${FIRMXRAY_HOME} \
	&& cd ${FIRMXRAY_HOME} \
	&& git clone https://github.com/OSUSecLab/FirmXRay.git \
	&& FIRMXRAY_GHIDRA_VERSION=10.0.4_PUBLIC \
	&& FIRMXRAY_GHIDRA_SHA256=1ce9bdf2d7f6bdfe5dccd06da828af31bc74acfd800f71ade021d5211e820d5e \
	&& FIRMXRAY_GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.0.4_build/ghidra_10.0.4_PUBLIC_20210928.zip \
	&& wget --progress=bar:force -O /tmp/ghidra_${FIRMXRAY_GHIDRA_VERSION}.zip ${FIRMXRAY_GHIDRA_URL} \
	&& echo "$FIRMXRAY_GHIDRA_SHA256 /tmp/ghidra_${FIRMXRAY_GHIDRA_VERSION}.zip" | sha256sum -c - \
	&& unzip -d ./ /tmp/ghidra_${FIRMXRAY_GHIDRA_VERSION}.zip \
	&& rm /tmp/ghidra_${FIRMXRAY_GHIDRA_VERSION}.zip \
	&& cd ghidra_${FIRMXRAY_GHIDRA_VERSION}/support \
	&& ./buildGhidraJar \
	&& mv ghidra.jar ${FIRMXRAY_HOME}/FirmXRay/lib \
	&& cd ${FIRMXRAY_HOME}/FirmXRay \
	&& make \
	&& echo "firmxray install complete."


##################################################
# cleanup 

RUN echo "===> Clear conda cache..." \
	&& mamba clean -t -y \
	&& mamba init

# RUN echo "===> Clean up unnecessary files..." \
#     && apt-get purge -y --auto-remove unzip curl \
#     && apt-get clean \
#     && rm -rf \
#     	# /var/lib/apt/lists/* \
#     	#/var/cache/apt/archives \
#     	/tmp/* \
#     	/var/tmp/* \
#     	${GHIDRA_HOME}/docs \
#     	${GHIDRA_HOME}/Extensions/Eclipse \
#     	${GHIDRA_HOME}/licenses

WORKDIR /home

ENTRYPOINT ["tini", "--"]
CMD [ "/bin/bash" ]
