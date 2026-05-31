from setuptools import setup, find_packages

setup(
    name='SubX',
    version='0.1.0',
    packages=find_packages(),
    include_package_data=True,
    package_data={
        'subx': ['data/*.txt'],
    },
    install_requires=[
        'requests',
        'dnspython',
        'rich',
        'click',
    ],
    entry_points={
        'console_scripts': [
            'subx=subx.cli:main',
        ],
    },
    author='Gemini CLI',
    description='A fast subdomain finder tool',
    python_requires='>=3.6',
)
