<?php

namespace Liberpater\Selinux;

use Symfony\Component\Process\Process;

class Selinux
{
    /**
     * Check if selinux is in enforcement mode
     * @return string Enforcing | Permissive | Disabled
     */
    public function getenforce(): string
    {
        $p = new Process(['getenforce']);
        $p->run();

        return trim($p->getOutput());
    }

    /**
     * Set selinux enforcement mode
     * @param bool $enforce True for enforcing
     * @return int Exit code of setenforce
     */
    public function setEnforce(bool $enforce): int
    {
        $args = ['setenforce'];
        $args[] = $enforce ? 1 : 0;
        $p = new Process($args);

        return $p->run();
    }

    /**
     * Get an selinux boolean value
     * @param string $sebool The selinux boolean name
     * @param bool $status True if you want to get the current status, false for the default status
     * @return bool True if set to on
     */
    public function getsebool(string $sebool, bool $status = true): bool
    {
        $result = false;
        $sebools = $this->getBools();

        $sestatus = $status ? 'status' : 'default';

        if (!empty($sebools) && array_key_exists($sebool, $sebools)) {
            $result = $sebools[$sebool][$sestatus] === 'on';
        }

        return $result;
    }

    /**
     * Get list of selinux booleans
     * @return array Parsed version of semanage boolean -l
     */
    public function getBools(): array
    {
        $sebools = [];

        $p = new Process(['semanage', 'boolean', '-l']);
        $p->run();
        $pattern = '/([^\s]+)\s+\((on|off)\s+,\s+(on|off)\)\s+(.*)/';
        $matches = [];
        preg_match_all($pattern, $p->getOutput(), $matches);

        $rules = $matches[1];
        $status = $matches[2];
        $default = $matches[3];
        $description = $matches[4];

        foreach ($rules as $id => $rule) {
            $sebools[$rule] = [
              'status' => $status[$id],
              'default' => $default[$id],
              'description' => $description[$id]
            ];
        }

        return $sebools;
    }


    /**
     * Set an selinux boolean
     * @param string $sebool Selinux bool to set
     * @param bool $status True if should be set to on
     * @param bool $permanent True if should be made default
     * @return int Return value of setsebool
     */
    public function setBool(string $sebool, bool $status, bool $permanent): int
    {

        $returnval = -1;

        $sebools = $this->getBools();
        // First let's check that the bool exists.
        if (array_key_exists($sebool, $sebools)) {
            $args = ['setsebool'];
            if ($permanent) {
                $args[] = '-P';
            }
            $args[] = $sebool;
            $args[] = $permanent ? 'on' : 'off';

            $p = new Process($args);
            $returnval = $p->run();
        }

        return $returnval;
    }

    /**
     * Get the contexts and level of files and directories
     * @param string $path Path to the file or directory
     * @param bool $directory If we should get the information of just a directory
     * @return array Contexts of files and directories found
     */
    public function getContext(string $path, $directory = false): array
    {
        $info = [];

        $args = ['ls', '--scontext', $path];
        if ($directory) {
            $args[] = '-d';
        }
        $p = new Process($args);
        $p->run();

        $pattern = '/([^:]+):([^:]+):([^:]+):([^\s]+)\s(.*)/';
        $matches = [];
        preg_match_all($pattern, $p->getOutput(), $matches);

        $files = $matches[5];

        foreach ($files as $id => $file) {
            $info[$file] = [
                'user'      => $matches[1][$id],
                'domain'    => $matches[2][$id],
                'type'      => $matches[3][$id],
                'level'     => $matches[4][$id],
            ];
        }

        return $info;
    }
}