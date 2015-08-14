<?php

class v100_ssl extends package_migration {
	public function up() {
		/* regen keys */
		require __DIR__.'/../../libraries/Ssl.php';
		
		/* this should generate the keys */
		$ssl = new Ssl();

		return true;
	}

	public function down() {
		require __DIR__.'/../../libraries/Ssl.php';
		
		$ssl = new ssl();
		
		$ssl->migration_down();

		return true;
	}

} /* end class */