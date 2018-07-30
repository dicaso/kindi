from setuptools import setup

package = "kindi"
version = "0.0.3"

setup(name = package,
      version = version,
      description='Kind incommunicados package for user secrets',
      long_description="""Kind incommunicados package 
for storing user [API] keys necessary for running
some programs/workflows.
""",
      url='https://github.com/dicaso/kindi',
      author = 'Christophe Van Neste',
      author_email = 'beukueb@gmail.com',
      license = 'GNU GENERAL PUBLIC LICENSE',
      packages = ['kindi'],
      install_requires = [
          'cryptography'
      ],
      extras_require = {
      },
      package_data = {
      },
      include_package_data = True,
      zip_safe = False,
      test_suite = 'nose.collector',
      tests_require = ['nose']
)

#To install with symlink, so that changes are immediately available:
#pip install -e .
