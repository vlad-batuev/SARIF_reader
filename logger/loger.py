import logging
from config.config import debug

logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.DEBUG if debug else logging.INFO
                    )

logger = logging.getLogger(__name__)