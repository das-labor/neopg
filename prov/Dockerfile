FROM ubuntu

# dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
		libsqlite3-dev \
		libbotan1.10-dev \
		libz-dev \
		bzip2 \
		gcovr \
		cppcheck \
		doxygen \
		lcov \
		git \
		libboost1.58 \
		pkg-config \
		libusb-1.0-0-dev \
		libbz2-dev \
		libgnutls-dev \
		git \
	&& rm -rf /var/lib/apt/lists/*

# build botan
RUN git clone https://github.com/randombit/botan.git
RUN cd botan \
	&& git checkout 2.3.0 \
	&& ./configure.py \
	&& make install
