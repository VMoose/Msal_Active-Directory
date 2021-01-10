class Config(object):
    # In a production app, store this instead in KeyVault or an environment variable
    # TODO: Enter your client secret from Azure AD below
    CLIENT_SECRET = ""

    # AUTHORITY = "https://login.microsoftonline.com/common"  # For multi-tenant app
    AUTHORITY = "https://login.microsoftonline.com/"

    # TODO: Enter your application client ID here
    CLIENT_ID = ""

    # TODO: Enter the redirect path you want to use for OAuth requests
    #   Note that this will be the end of the URI entered back in Azure AD
    REDIRECT_PATH = "/"  # Used to form an absolute URL,
    # which must match your app's redirect_uri set in AAD

    # You can find the proper permission names from this document
    # https://docs.microsoft.com/en-us/graph/permissions-reference
    SCOPE = ["User.Read"]

    SESSION_TYPE = "filesystem"  # So token cache will be stored in server-side session

    IMAGE_NAME = 'profile.JPG'  # image file name

    SAVE_AS = "FlaskExercise/static/images/" + IMAGE_NAME  # Path where image should be saved

    GRAPH_USER_URL = 'https://graph.microsoft.com/v1.0/me/'  # Graph API Url to extract user info

    GRAPH_IMAGE_URL = 'https://graph.microsoft.com/beta/me/photo/$value'  # Graph API Url to extract user image
