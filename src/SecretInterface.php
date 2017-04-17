<?php
namespace Secret;
/**
 * Interface SecretInterface
 * @package Secret
 */
interface SecretInterface
{

    /**
     * decode use ssl
     *
     * @param string $data
     * @return mixed
     */
    public function decode($data = '');

    /**
     * encode use ssl
     *
     * @param string $data
     * @param null $type
     * @return mixed
     */
    public function encode($data = '', $type = null);

}
