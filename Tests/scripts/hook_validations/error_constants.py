class Error:
    @staticmethod
    def wrong_file_extension(file_extension, accepted_extensions):
        return "File extension {} is not valid. accepted {}".format(file_extension, accepted_extensions)
