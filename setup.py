"""setuptools packaging."""

import setuptools

setuptools.setup(
    name="ucfs-claimant-api-replayer",
    version="0.0.1",
    author="DWP DataWorks",
    author_email="dataworks@digital.uc.dwp.gov.uk",
    description="Lambda for replaying requests to V1 API gateway",
    long_description="Lambda for replaying requests to V1 API gateway",
    long_description_content_type="text/markdown",
    entry_points={"console_scripts": ["replayer=replayer:main"]},
    package_dir={"": "src"},
    packages=setuptools.find_packages("src"),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
