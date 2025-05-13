# BACKEND
class InvalidSigmAIQBackend(Exception):
    """
    Exception for the :class:`Generic SigmAIQ Backend Factory
    <sigmaiq.sigma_backend_factory>` factory.

    To be used when the selected backend in the factory is invalid.
    """


class InvalidOutputFormat(Exception):
    """
    Exception for the :class:`Generic SigmAIQ Backend Class
    <sigmaiq.sigma_backend_class>` class.

    To be used when the specified output_format for the class is invalid.
    """


# PIPELINE
class InvalidSigmAIQPipeline(Exception):
    """
    Exception for the :class:`Generic SigmAIQ Pipeline Factory
    <sigmaiq.sigma_pipeline_factory>` factory.

    To be used when the provided processing_pipeline in the factory is invalid.
    """


class InvalidCustomFieldMapping(Exception):
    """
    Exception for the :class:`Generic SigmAIQ Pipeline Factory
    <sigmaiq.sigma_pipeline_factory.SigmAIQPipeline>` factory.

    To be used when the provided field mapping to the classmethod `from_fieldmap()`
    in the factory is invalid or empty.
    """


# RULEBUILDER
class InvalidSigmaRuleFilepath(Exception):
    """For use when the Sigma Rule Filepath in globals is not set or invalid"""


class InvalidIOCField(Exception):
    """For use when ioc_field or ioc_value isn't in an IOC dictionary used for creating detections"""
